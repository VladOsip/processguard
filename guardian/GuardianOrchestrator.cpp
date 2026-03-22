#include "GuardianOrchestrator.hpp"
#include "ProcessAttacher.hpp"
#include "Logger.hpp"

namespace pg {

GuardianOrchestrator::GuardianOrchestrator(std::wstring targetName,
                                             std::chrono::milliseconds pollInterval)
    : m_targetName(std::move(targetName))
    , m_pollInterval(pollInterval)
{}

GuardianOrchestrator::~GuardianOrchestrator() {
    m_dispatcher.stop();
}

// ---------------------------------------------------------------------------
// initialize()
//
// Two modes depending on whether a launch path was set:
//
//   Launch mode: calls ProcessAttacher::launchSuspended to create the target
//     frozen at its first instruction. After all monitors are initialised,
//     ResumeThread starts it. The initialization race is eliminated.
//
//   Attach mode: calls ProcessAttacher::findAndOpen on an existing process.
//     The initialization race exists but the code is otherwise unchanged.
//
// In both cases we detect the target's bitness after obtaining the handle
// and forward it to ModuleWatchdog and MemoryIntegrityMonitor.
// ---------------------------------------------------------------------------

Result<void, OrchestratorError> GuardianOrchestrator::initialize() {
    constexpr DWORD ACCESS = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

    if (m_launchPath) {
        Logger::info("Launch mode: starting '{}' suspended",
                     std::string(m_launchPath->begin(), m_launchPath->end()));

        auto launchResult = ProcessAttacher::launchSuspended(*m_launchPath);
        if (!launchResult)
            return std::unexpected(OrchestratorError{
                "launchSuspended failed: " + launchResult.error().detail
            });

        m_hTarget     = std::move(launchResult->processHandle);
        m_hMainThread = std::move(launchResult->threadHandle);
        m_targetPid   = launchResult->pid;

        Logger::info("Target launched suspended, PID {}", m_targetPid);
    }
    else {
        Logger::info("Attach mode: searching for '{}'",
                     std::string(m_targetName.begin(), m_targetName.end()));

        auto attachResult = ProcessAttacher::findAndOpen(m_targetName, ACCESS);
        if (!attachResult)
            return std::unexpected(OrchestratorError{
                "Failed to attach: " + attachResult.error().detail
            });
        m_hTarget = std::move(*attachResult);

        auto pidResult = ProcessAttacher::findByName(m_targetName);
        if (!pidResult)
            return std::unexpected(OrchestratorError{ "Failed to get target PID" });
        m_targetPid = *pidResult;
    }

    // Detect bitness: read the COFF Machine field from the target's PE headers.
    // We peek at the DOS header then the NT signature + FileHeader.
    {
        HMODULE hMods[1]{};
        DWORD   needed{};
        if (EnumProcessModulesEx(m_hTarget.get(), hMods, sizeof(hMods),
                                  &needed, LIST_MODULES_ALL))
        {
            IMAGE_DOS_HEADER dosHdr{};
            SIZE_T bytesRead{};
            if (ReadProcessMemory(m_hTarget.get(),
                                   reinterpret_cast<LPCVOID>(
                                       reinterpret_cast<uintptr_t>(hMods[0])),
                                   &dosHdr, sizeof(dosHdr), &bytesRead)
                && dosHdr.e_magic == IMAGE_DOS_SIGNATURE)
            {
                DWORD sig{};
                IMAGE_FILE_HEADER fh{};
                uintptr_t ntAddr = reinterpret_cast<uintptr_t>(hMods[0])
                                 + dosHdr.e_lfanew;
                ReadProcessMemory(m_hTarget.get(),
                                   reinterpret_cast<LPCVOID>(ntAddr),
                                   &sig, sizeof(sig), &bytesRead);
                ReadProcessMemory(m_hTarget.get(),
                                   reinterpret_cast<LPCVOID>(ntAddr + sizeof(DWORD)),
                                   &fh, sizeof(fh), &bytesRead);
                m_is32BitTarget = (fh.Machine == IMAGE_FILE_MACHINE_I386);
                Logger::info("Target bitness: {}-bit",
                             m_is32BitTarget ? 32 : 64);
            }
        }
    }

    setupHandlers();
    return initMonitors();
}

// ---------------------------------------------------------------------------
// initMonitors()
//
// Constructs all four monitors now that we have a valid handle and PID.
// In launch mode this runs while the target is still suspended, guaranteeing
// the baseline snapshots reflect the pristine pre-execution state.
// After this returns, run() calls ResumeThread if in launch mode.
// ---------------------------------------------------------------------------

Result<void, OrchestratorError> GuardianOrchestrator::initMonitors() {
    // --- Memory Integrity Monitor ---
    m_memMonitor = std::make_unique<MemoryIntegrityMonitor>(
        m_hTarget.get(),
        [this](SecurityEvent e) { m_dispatcher.post(std::move(e)); }
    );
    if (auto r = m_memMonitor->initialize(); !r)
        return std::unexpected(OrchestratorError{
            "MemoryIntegrityMonitor init failed: " + r.error().message
        });

    // --- Module Watchdog ---
    m_moduleWatchdog = std::make_unique<ModuleWatchdog>(
        m_hTarget.get(),
        [this](SecurityEvent e) { m_dispatcher.post(std::move(e)); },
        m_is32BitTarget
    );
    if (auto r = m_moduleWatchdog->initialize(); !r)
        return std::unexpected(OrchestratorError{
            "ModuleWatchdog init failed: " + r.error().message
        });

    // --- ETW Session Monitor ---
    m_etwMonitor = std::make_unique<EtwSessionMonitor>(
        m_targetPid,
        [this](SecurityEvent e) { m_dispatcher.post(std::move(e)); }
    );
    if (auto r = m_etwMonitor->start(); !r)
        Logger::warn("ETW monitor failed to start ({}). Continuing without ETW.",
                     r.error().message);

    // --- Heartbeat Monitor ---
    m_heartbeatMonitor = std::make_unique<HeartbeatMonitor>(
        [this](SecurityEvent e) { m_dispatcher.post(std::move(e)); },
        std::chrono::milliseconds(2000)
    );
    if (auto r = m_heartbeatMonitor->start(); !r)
        return std::unexpected(OrchestratorError{
            "HeartbeatMonitor failed to start: " + r.error().message
        });

    Logger::info("All monitors initialised. Protecting PID {}.", m_targetPid);
    return {};
}

// ---------------------------------------------------------------------------
// run()
// ---------------------------------------------------------------------------

void GuardianOrchestrator::run() {
    m_memThread = std::jthread([this](std::stop_token st) {
        memoryMonitorLoop(std::move(st));
    });
    m_moduleThread = std::jthread([this](std::stop_token st) {
        moduleWatchdogLoop(std::move(st));
    });

    // In launch mode, all monitors are live -- safe to let the target run.
    if (m_hMainThread) {
        Logger::info("Resuming suspended target (PID {})", m_targetPid);
        ResumeThread(m_hMainThread.get());
    }

    m_dispatcher.run();  // blocks until shutdown()
}

// ---------------------------------------------------------------------------
// shutdown()
// ---------------------------------------------------------------------------

void GuardianOrchestrator::shutdown() {
    Logger::info("Shutdown requested");
    m_memThread.request_stop();
    m_moduleThread.request_stop();
    if (m_etwMonitor)       m_etwMonitor->stop();
    if (m_heartbeatMonitor) m_heartbeatMonitor->stop();
    m_dispatcher.stop();
}

// ---------------------------------------------------------------------------
// setupHandlers()
// ---------------------------------------------------------------------------

void GuardianOrchestrator::setupHandlers() {
    m_dispatcher.registerCatchAll([](const SecurityEvent& e) {
        Logger::warn("ALERT | type={} | {}{}",
                     static_cast<int>(e.type),
                     e.description,
                     e.detail.empty() ? "" : " | " + e.detail);
    });

    m_dispatcher.registerHandler(EventType::TargetExited,
        [this](const SecurityEvent&) {
            Logger::info("Target process has exited. Shutting down.");
            shutdown();
        });

    m_dispatcher.registerHandler(EventType::ThreadsSuspended,
        [](const SecurityEvent& e) {
            Logger::error("*** THREAD SUSPENSION DETECTED *** {}", e.detail);
            Logger::warn("Target is frozen -- consider resuming threads or restarting");
        });

    m_dispatcher.registerHandler(EventType::HeartbeatRestored,
        [](const SecurityEvent&) {
            Logger::info("Target heartbeat restored -- threads running normally");
        });
}

// ---------------------------------------------------------------------------
// targetAlive()
// ---------------------------------------------------------------------------

bool GuardianOrchestrator::targetAlive() const {
    if (!m_hTarget) return false;
    return WaitForSingleObject(m_hTarget.get(), 0) == WAIT_TIMEOUT;
}

// ---------------------------------------------------------------------------
// memoryMonitorLoop()
// ---------------------------------------------------------------------------

void GuardianOrchestrator::memoryMonitorLoop(std::stop_token token) {
    Logger::info("Memory monitor thread started");

    while (!token.stop_requested()) {
        if (!targetAlive()) {
            m_dispatcher.post(SecurityEvent{
                .type        = EventType::TargetExited,
                .description = "Target process exited"
            });
            return;
        }

        m_memMonitor->poll();

        auto deadline = std::chrono::steady_clock::now() + m_pollInterval;
        while (!token.stop_requested() &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    Logger::info("Memory monitor thread exiting");
}

// ---------------------------------------------------------------------------
// moduleWatchdogLoop()
// ---------------------------------------------------------------------------

void GuardianOrchestrator::moduleWatchdogLoop(std::stop_token token) {
    Logger::info("Module watchdog thread started");

    while (!token.stop_requested()) {
        if (!targetAlive()) return;

        m_moduleWatchdog->poll();

        auto deadline = std::chrono::steady_clock::now() + m_pollInterval;
        while (!token.stop_requested() &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    Logger::info("Module watchdog thread exiting");
}

} // namespace pg
