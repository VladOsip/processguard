#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include "Result.hpp"
#include "WinHandle.hpp"
#include "EventDispatcher.hpp"
#include "MemoryIntegrityMonitor.hpp"
#include "ModuleWatchdog.hpp"
#include "EtwSessionMonitor.hpp"
#include "HeartbeatMonitor.hpp"

namespace pg {

struct OrchestratorError {
    std::string message;
};

// ---------------------------------------------------------------------------
// GuardianOrchestrator  (C++23 edition)
//
// New capability: launch mode vs attach mode.
//
//   Attach mode (original):
//     Guardian finds and attaches to an already-running target.
//     The initialization race exists: an attacker who acts between target
//     startup and guardian attach is not detected.
//
//   Launch mode (new):
//     Guardian launches the target with CREATE_SUSPENDED, takes the full
//     baseline snapshot before the target has executed a single instruction,
//     then resumes it. The initialization race is eliminated.
//     Use via: GuardianOrchestrator::withLaunchPath(L"target.exe")
//
// The is32BitTarget flag is forwarded to ModuleWatchdog and
// MemoryIntegrityMonitor so they use the correct WOW64-aware APIs.
// ---------------------------------------------------------------------------

class GuardianOrchestrator {
public:
    // Attach to an already-running process by image name.
    explicit GuardianOrchestrator(
        std::wstring targetName,
        std::chrono::milliseconds pollInterval = std::chrono::milliseconds(1000));

    ~GuardianOrchestrator();

    GuardianOrchestrator(const GuardianOrchestrator&)            = delete;
    GuardianOrchestrator& operator=(const GuardianOrchestrator&) = delete;

    // Optional: set the full path to launch the target suspended.
    // If set, initialize() will launch the target rather than finding it.
    void setLaunchPath(std::wstring exePath) {
        m_launchPath = std::move(exePath);
    }

    Result<void, OrchestratorError> initialize();
    void run();
    void shutdown();

private:
    void setupHandlers();
    bool targetAlive() const;
    void memoryMonitorLoop(std::stop_token token);
    void moduleWatchdogLoop(std::stop_token token);

    // Initialise monitors after we have a handle and PID.
    Result<void, OrchestratorError> initMonitors();

    std::wstring              m_targetName;
    std::optional<std::wstring> m_launchPath;
    std::chrono::milliseconds m_pollInterval;

    WinHandle  m_hTarget;
    WinHandle  m_hMainThread;  // only set in launch mode; used to resume target
    DWORD      m_targetPid{ 0 };
    bool       m_is32BitTarget{ false };

    std::unique_ptr<MemoryIntegrityMonitor> m_memMonitor;
    std::unique_ptr<ModuleWatchdog>         m_moduleWatchdog;
    std::unique_ptr<EtwSessionMonitor>      m_etwMonitor;
    std::unique_ptr<HeartbeatMonitor>       m_heartbeatMonitor;
    EventDispatcher                         m_dispatcher;

    std::jthread m_memThread;
    std::jthread m_moduleThread;
};

} // namespace pg
