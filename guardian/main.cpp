#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>
#include <string>

#include "GuardianOrchestrator.hpp"
#include "Logger.hpp"

// ---------------------------------------------------------------------------
// Guardian entry point  (C++23 edition)
//
// Usage:
//   guardian.exe [target-image-name] [poll-interval-ms] [--launch <exe-path>]
//
//   target-image-name  : image name to search for in attach mode (default: target.exe)
//   poll-interval-ms   : polling interval in milliseconds (default: 1000)
//   --launch <path>    : launch the target suspended rather than attaching;
//                        eliminates the initialization race
//
// Examples:
//   guardian.exe target.exe 1000
//   guardian.exe target.exe 1000 --launch C:\path\to\target.exe
//
// Must be run as Administrator for ETW kernel session support.
// ---------------------------------------------------------------------------

static pg::GuardianOrchestrator* g_orchestrator = nullptr;

static BOOL WINAPI ctrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        if (g_orchestrator) {
            std::cout << "\n[!] Ctrl+C received -- shutting down...\n";
            g_orchestrator->shutdown();
        }
        return TRUE;
    }
    return FALSE;
}

int wmain(int argc, wchar_t* argv[]) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  mode{};
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    std::wstring targetName   = (argc >= 2) ? argv[1] : L"target.exe";
    auto         pollMs       = (argc >= 3)
        ? std::chrono::milliseconds(std::stoi(argv[2]))
        : std::chrono::milliseconds(1000);

    // Check for --launch flag
    std::optional<std::wstring> launchPath;
    for (int i = 3; i < argc - 1; ++i) {
        if (std::wstring_view(argv[i]) == L"--launch") {
            launchPath = argv[i + 1];
            break;
        }
    }

    Logger::info("ProcessGuard starting -- target: {}, poll: {}ms{}",
                 std::string(targetName.begin(), targetName.end()),
                 pollMs.count(),
                 launchPath ? " [launch mode]" : " [attach mode]");

    SetConsoleCtrlHandler(ctrlHandler, TRUE);

    pg::GuardianOrchestrator orchestrator(targetName, pollMs);
    if (launchPath)
        orchestrator.setLaunchPath(*launchPath);

    g_orchestrator = &orchestrator;

    auto initResult = orchestrator.initialize();
    if (!initResult) {
        Logger::error("Initialization failed: {}", initResult.error().message);
        return 1;
    }

    orchestrator.run();

    Logger::info("ProcessGuard exiting cleanly");
    return 0;
}
