#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

// ---------------------------------------------------------------------------
// Target Process — Active Heartbeat Sender
//
// Rather than passively waiting for the guardian to ping us (which has a
// fundamental flaw: the target could respond to one last ping right before
// being suspended), we instead PUSH a heartbeat to the guardian every
// HEARTBEAT_INTERVAL_MS milliseconds.
//
// If the target's threads are suspended, it cannot push anything. The
// guardian notices the silence and raises a ThreadsSuspended alert.
//
// The heartbeat is a named pipe CLIENT — the guardian is the server.
// Pipe name: \\.\pipe\ProcessGuardHeartbeat
//
// Protocol:
//   Target writes: "HB:<pid>\n"  every HEARTBEAT_INTERVAL_MS ms.
//   Guardian reads and timestamps each received beat.
//   If no beat arrives within SILENCE_THRESHOLD_MS, alert fires.
//
// Why active (push) beats are better than passive (poll) pings:
//   A poll-based approach has a race window. Suppose the guardian pings every
//   1000ms and the attacker suspends threads at t=999ms. The guardian won't
//   poll again for 1ms. But during that 1ms, if a ping was already in-flight,
//   the target might respond before suspension fully takes hold. With a push
//   model, the moment the target is suspended it simply stops sending — no
//   race window.
// ---------------------------------------------------------------------------

static std::atomic<bool> g_running{true};

static BOOL WINAPI ctrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        std::cout << "\n[Target] Ctrl+C — shutting down\n";
        g_running = false;
        return TRUE;
    }
    return FALSE;
}

constexpr int HEARTBEAT_INTERVAL_MS = 500;
constexpr wchar_t PIPE_NAME[] = L"\\\\.\\pipe\\ProcessGuardHeartbeat";

// Heartbeat sender — runs on a dedicated thread so that even if the main
// thread is busy, beats keep flowing at a consistent rate.
//
// We deliberately use a separate thread rather than sending beats from main()
// so that the heartbeat rate is independent of whatever work the target is
// doing. In a real agent, this thread would run at HIGH_PRIORITY_CLASS.
static void heartbeatThread() {
    std::string beatMsg = "HB:" + std::to_string(GetCurrentProcessId()) + "\n";
    int beatCount = 0;

    while (g_running) {
        // Try to connect to the guardian's pipe server.
        // WaitNamedPipe blocks up to 500ms if the pipe isn't ready yet,
        // then we retry rather than failing hard — the guardian might still
        // be starting up.
        BOOL connected = WaitNamedPipeW(PIPE_NAME, 500);
        if (!connected) {
            // Guardian not listening yet — keep trying silently.
            continue;
        }

        HANDLE hPipe = CreateFileW(
            PIPE_NAME,
            GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            // Pipe server not ready — retry next cycle.
            std::this_thread::sleep_for(std::chrono::milliseconds(HEARTBEAT_INTERVAL_MS));
            continue;
        }

        DWORD written{};
        BOOL ok = WriteFile(hPipe, beatMsg.c_str(),
                            static_cast<DWORD>(beatMsg.size()),
                            &written, nullptr);
        CloseHandle(hPipe);

        if (ok) {
            ++beatCount;
            // Only log every 10 beats to keep the target's console readable.
            if (beatCount % 10 == 0) {
                std::cout << "[Target] Heartbeat #" << beatCount << " sent\n";
            }
        }

        // Sleep between beats. This sleep is the key suspension indicator:
        // if all threads are suspended, this sleep never completes and the
        // next beat is never sent.
        std::this_thread::sleep_for(std::chrono::milliseconds(HEARTBEAT_INTERVAL_MS));
    }
}

int main() {
    SetConsoleCtrlHandler(ctrlHandler, TRUE);

    std::cout << "================================================\n"
              << "  ProcessGuard TARGET PROCESS\n"
              << "  PID:       " << GetCurrentProcessId() << '\n'
              << "  Heartbeat: " << HEARTBEAT_INTERVAL_MS << "ms interval\n"
              << "  Pipe:      " << "\\\\.\\pipe\\ProcessGuardHeartbeat" << '\n'
              << "================================================\n\n";

    // Start the heartbeat sender thread.
    std::thread hbThread(heartbeatThread);

    int tick = 0;
    while (g_running) {
        std::cout << "[Target] Tick " << ++tick
                  << " — alive (PID " << GetCurrentProcessId() << ")\n";

        for (int i = 0; i < 20 && g_running; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    std::cout << "[Target] Exiting\n";
    hbThread.join();
    return 0;
}
