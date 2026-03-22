#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <chrono>
#include <string>

#include "HeartbeatMonitor.hpp"
#include "Logger.hpp"

namespace pg {

using namespace std::chrono;

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

HeartbeatMonitor::HeartbeatMonitor(AlertCallback cb,
                                    milliseconds silenceThreshold)
    : m_onAlert(std::move(cb))
    , m_silenceThreshold(silenceThreshold)
{}

HeartbeatMonitor::~HeartbeatMonitor() {
    stop();
}

// ---------------------------------------------------------------------------
// start()
// ---------------------------------------------------------------------------

Result<void, HeartbeatError> HeartbeatMonitor::start() {
    // Initialise the last-beat timestamp to now so the watchdog doesn't
    // immediately alert before the target has had a chance to connect.
    auto now = system_clock::now().time_since_epoch();
    m_lastBeatNs.store(duration_cast<nanoseconds>(now).count());

    m_listenerThread = std::jthread([this](std::stop_token st) {
        listenerLoop(std::move(st));
    });

    m_watchdogThread = std::jthread([this](std::stop_token st) {
        watchdogLoop(std::move(st));
    });

    Logger::info("HeartbeatMonitor started (silence threshold: {}ms)",
                 m_silenceThreshold.count());
    return {};
}

// ---------------------------------------------------------------------------
// stop()
// ---------------------------------------------------------------------------

void HeartbeatMonitor::stop() {
    // jthreads request_stop() + join() happen automatically on destruction,
    // but we might call stop() explicitly before destruction (e.g. during
    // orchestrator shutdown). Guard against double-stop.
    m_listenerThread.request_stop();
    m_watchdogThread.request_stop();

    // Unblock any pending ConnectNamedPipe by creating a throwaway client.
    // Without this, the listener thread could block indefinitely on
    // ConnectNamedPipe even after stop_requested() is true.
    HANDLE hWake = CreateFileW(PIPE_NAME, GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING, 0, nullptr);
    if (hWake != INVALID_HANDLE_VALUE) CloseHandle(hWake);
}

// ---------------------------------------------------------------------------
// msSinceLastBeat()
// ---------------------------------------------------------------------------

long long HeartbeatMonitor::msSinceLastBeat() const {
    auto lastNs  = m_lastBeatNs.load();
    auto nowNs   = duration_cast<nanoseconds>(
                       system_clock::now().time_since_epoch()).count();
    return (nowNs - lastNs) / 1'000'000LL;
}

// ---------------------------------------------------------------------------
// listenerLoop()
//
// Runs on m_listenerThread. Creates a named pipe server instance, waits for
// the target to connect, reads heartbeat messages, and timestamps each one.
// When the target disconnects (or suspends and the pipe times out), we create
// a new server instance and wait again.
//
// We use overlapped I/O with a timeout on ReadFile so that the thread can
// respond to stop_requested() even when no data is arriving — otherwise the
// thread would block forever on a suspended target.
// ---------------------------------------------------------------------------

void HeartbeatMonitor::listenerLoop(std::stop_token token) {
    Logger::info("Heartbeat listener thread started — pipe: {}",
                 std::string(PIPE_NAME, PIPE_NAME + wcslen(PIPE_NAME)));

    while (!token.stop_requested()) {
        // Create a new pipe server instance for each connection cycle.
        HANDLE hPipe = CreateNamedPipeW(
            PIPE_NAME,
            PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            256, 256,
            0, nullptr
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            Logger::error("HeartbeatMonitor: CreateNamedPipe failed ({})",
                          GetLastError());
            std::this_thread::sleep_for(milliseconds(500));
            continue;
        }

        // Wait for the target to connect using overlapped I/O so we can
        // honour stop_requested() without blocking indefinitely.
        OVERLAPPED ov{};
        ov.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

        BOOL connected = ConnectNamedPipe(hPipe, &ov);
        DWORD err      = GetLastError();

        if (!connected && err == ERROR_IO_PENDING) {
            // Wait up to 500ms at a time so we can check stop_requested().
            while (!token.stop_requested()) {
                DWORD wait = WaitForSingleObject(ov.hEvent, 500);
                if (wait == WAIT_OBJECT_0) {
                    connected = TRUE;
                    break;
                }
            }
        } else if (err == ERROR_PIPE_CONNECTED) {
            connected = TRUE;
        }

        CloseHandle(ov.hEvent);

        if (!connected || token.stop_requested()) {
            CloseHandle(hPipe);
            continue;
        }

        Logger::info("Heartbeat: target connected to pipe");

        // Read loop — each ReadFile with a timeout.
        // We use overlapped I/O again so we're never stuck if the target
        // suspends mid-read.
        while (!token.stop_requested()) {
            char buf[256]{};
            DWORD bytesRead{};

            OVERLAPPED readOv{};
            readOv.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

            BOOL ok = ReadFile(hPipe, buf, sizeof(buf) - 1, nullptr, &readOv);
            err     = GetLastError();

            if (!ok && err == ERROR_IO_PENDING) {
                // Wait up to 500ms — short enough to feel responsive.
                DWORD wait = WaitForSingleObject(readOv.hEvent, 500);
                if (wait == WAIT_OBJECT_0) {
                    GetOverlappedResult(hPipe, &readOv, &bytesRead, FALSE);
                    ok = TRUE;
                } else {
                    // Timeout — no data in 500ms. Don't disconnect yet;
                    // the watchdog handles the silence threshold logic.
                    CloseHandle(readOv.hEvent);
                    CancelIo(hPipe);
                    continue;
                }
            }

            CloseHandle(readOv.hEvent);

            if (!ok) {
                // Client disconnected or pipe broken.
                Logger::debug("Heartbeat pipe disconnected ({})", GetLastError());
                break;
            }

            if (bytesRead > 0) {
                buf[bytesRead] = '\0';
                // Stamp the received time.
                auto nowNs = duration_cast<nanoseconds>(
                                 system_clock::now().time_since_epoch()).count();
                m_lastBeatNs.store(nowNs);
                m_hasEverBeaten.store(true);
                Logger::debug("Heartbeat received: {}", buf);
            }
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    Logger::info("Heartbeat listener thread exiting");
}

// ---------------------------------------------------------------------------
// watchdogLoop()
//
// Runs on m_watchdogThread. Checks the silence duration every 200ms and
// fires alerts when thresholds are crossed. Tracks state to avoid spamming
// repeated alerts for the same suspension event.
// ---------------------------------------------------------------------------

void HeartbeatMonitor::watchdogLoop(std::stop_token token) {
    Logger::info("Heartbeat watchdog thread started");

    // Don't alert until the target has sent at least one beat — avoids
    // false positives during the startup window when the target hasn't
    // connected to the pipe yet.
    while (!token.stop_requested() && !m_hasEverBeaten.load()) {
        std::this_thread::sleep_for(milliseconds(200));
    }

    if (token.stop_requested()) return;
    Logger::info("Heartbeat watchdog: first beat received — monitoring active");

    while (!token.stop_requested()) {
        std::this_thread::sleep_for(milliseconds(200));

        long long silenceMs = msSinceLastBeat();
        bool currentlySuspended = m_suspended.load();

        if (!currentlySuspended && silenceMs >= m_silenceThreshold.count()) {
            // Transition: normal → suspended
            m_suspended.store(true);

            std::string detail = "Silence duration: " + std::to_string(silenceMs)
                               + "ms (threshold: "
                               + std::to_string(m_silenceThreshold.count()) + "ms)";

            Logger::error("HEARTBEAT LOST — target threads likely suspended! ({})",
                          detail);
            m_onAlert(makeSuspendEvent(detail));

        } else if (currentlySuspended && silenceMs < m_silenceThreshold.count()) {
            // Transition: suspended → recovered
            m_suspended.store(false);

            Logger::info("Heartbeat RESTORED — target threads are running again");
            m_onAlert(makeHeartbeatRestoredEvent());
        }
    }

    Logger::info("Heartbeat watchdog thread exiting");
}

} // namespace pg
