#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <string>
#include <thread>

#include "Result.hpp"
#include "Events.hpp"
#include "WinHandle.hpp"

namespace pg {

// ----------------------------------------------------------------------------
// HeartbeatMonitor
//
// Listens for periodic heartbeat messages pushed by the target process over
// a named pipe. If no beat arrives within the silence threshold, a
// ThreadsSuspended alert is raised.
//
// Why this detects thread suspension:
//   When all threads in a process are suspended via SuspendThread, no user-mode
//   code in that process executes — including our heartbeat sender thread.
//   The pipe goes silent. The guardian notices after at most
//   SILENCE_THRESHOLD_MS milliseconds.
//
// Why we are the pipe SERVER (not the client):
//   The guardian is the longer-lived, more trusted process. It makes sense for
//   it to own the pipe endpoint. The target connects and writes; the guardian
//   just listens. If the guardian crashes, the target can detect the broken
//   pipe too — bidirectional failure detection.
//
// Alert states:
//   Normal     → beats arriving within threshold
//   Suspended  → silence exceeds threshold → ThreadsSuspended event fired
//   Recovered  → beats resume after a suspended period → HeartbeatRestored event fired
//
// The monitor distinguishes "never connected" (target not started yet) from
// "was connected and went silent" (genuine suspension) to avoid false positives
// during startup.
// ----------------------------------------------------------------------------

struct HeartbeatError {
    std::string message;
    DWORD       winCode{0};
};

class HeartbeatMonitor {
public:
    using AlertCallback = std::function<void(SecurityEvent)>;

    // silenceThreshold: how long without a beat before we alert.
    // Recommended: 3-5x the target's heartbeat interval (target sends every 500ms,
    // so 2000ms gives a comfortable margin before false-positiving).
    explicit HeartbeatMonitor(AlertCallback cb,
                               std::chrono::milliseconds silenceThreshold
                                   = std::chrono::milliseconds(2000));

    ~HeartbeatMonitor();

    // Start the pipe server and the listener thread.
    Result<void, HeartbeatError> start();

    // Stop the listener thread and close the pipe.
    void stop();

    // True if at least one heartbeat has been received.
    bool hasEverBeaten() const noexcept { return m_hasEverBeaten.load(); }

    // True if currently in the suspended (silence) state.
    bool isSuspended() const noexcept { return m_suspended.load(); }

    // Milliseconds since the last heartbeat was received.
    long long msSinceLastBeat() const;

private:
    static constexpr wchar_t PIPE_NAME[] = L"\\\\.\\pipe\\ProcessGuardHeartbeat";

    // Pipe listener — blocks on ConnectNamedPipe + ReadFile in a loop.
    void listenerLoop(std::stop_token token);

    // Watchdog — periodically checks the timestamp and fires alerts.
    void watchdogLoop(std::stop_token token);

    AlertCallback             m_onAlert;
    std::chrono::milliseconds m_silenceThreshold;

    // Timestamp of the most recently received heartbeat.
    // Written by the listener thread, read by the watchdog thread.
    // Using atomic time_point via a wrapped int64 (nanoseconds since epoch).
    std::atomic<int64_t> m_lastBeatNs{0};

    std::atomic<bool> m_hasEverBeaten{false};
    std::atomic<bool> m_suspended{false};   // current alert state

    std::jthread m_listenerThread;
    std::jthread m_watchdogThread;
};

} // namespace pg
