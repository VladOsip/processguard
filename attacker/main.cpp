#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <filesystem>
#include <iostream>
#include <string>

#include "AttackTypes.hpp"
#include "AttackerUtils.hpp"
#include "Attacks.hpp"

// ---------------------------------------------------------------------------
// Attacker entry point
//
// Usage:
//   attacker.exe <mode> [target-image-name]
//
// Modes:
//   terminate    Kill the target process outright.
//                Guardian detection: ETW (immediate)
//
//   inject       Inject payload.dll into the target via LoadLibrary technique.
//                Guardian detection: ModuleWatchdog (poll-based, ~1s latency)
//                Requires: payload.dll in the same directory as attacker.exe
//
//   patch        Corrupt the target's .text section with INT3 bytes.
//                Guardian detection: MemoryIntegrityMonitor (poll-based, ~1s)
//
//   suspend      Freeze all target threads (guardian does NOT detect this).
//                Educational: demonstrates polling blind spots.
//                Threads are resumed after 5 seconds.
//
//   handle-leak  Open PROCESS_ALL_ACCESS handle and hold it.
//                Guardian detection: ETW (on the OpenProcess call).
//                Demonstrates detection-without-prevention.
//
// Default target: target.exe
// ---------------------------------------------------------------------------

static void printBanner() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12); // red
    std::cout << R"(
  ____  ____   __    ___  ____  ____  ___  _  _    __    ____  ____  __    ___  __ _  ____  ____
 |  _ \|  _ \ /  \  / __)|  __)|  __)/ __|| || |  /  \  |  __|  __||  |  / __)|  / )|  __||  _ \
 |  __/|    /| () || |__ | |_  | |_ \__ \|  __| | () | | |_  | |_  | |_| |__ >| . < | |_  |    /
 |__|  |_|\_\ \__/  \___)|____)|____)(___/|_||_|  \__/  |____||____||___|\___/|_|\_\|____||_|\_\
)";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
    std::cout << "\n  ProcessGuard Attack Simulator — educational use only\n\n";
}

static void printUsage(const char* exe) {
    std::cout << "Usage: " << exe << " <mode> [target-image-name]\n\n";
    std::cout << "Modes:\n";
    std::cout << "  terminate    Kill the target (ETW detection — immediate)\n";
    std::cout << "  inject       DLL injection via LoadLibrary (ModuleWatchdog — ~1s)\n";
    std::cout << "  patch        .text memory corruption (MemoryIntegrityMonitor — ~1s)\n";
    std::cout << "  suspend      Freeze all threads (NOT detected — blind spot demo)\n";
    std::cout << "  handle-leak  Hold PROCESS_ALL_ACCESS handle (ETW — immediate)\n\n";
    std::cout << "Default target image name: target.exe\n\n";
    std::cout << "Example:\n";
    std::cout << "  attacker.exe terminate\n";
    std::cout << "  attacker.exe inject\n";
    std::cout << "  attacker.exe patch target.exe\n";
}

int main(int argc, char* argv[]) {
    // Enable ANSI/VT colour sequences.
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode{};
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    printBanner();

    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    atk::AttackMode attackMode = atk::parseMode(argv[1]);
    if (attackMode == atk::AttackMode::Unknown) {
        atk::printFail("Unknown attack mode: " + std::string(argv[1]));
        printUsage(argv[0]);
        return 1;
    }

    std::wstring targetName = (argc >= 3)
        ? std::wstring(argv[2], argv[2] + strlen(argv[2]))
        : L"target.exe";

    // -----------------------------------------------------------------------
    // Find the target process.
    // -----------------------------------------------------------------------
    atk::printStep("Searching for target process: " +
                   std::string(targetName.begin(), targetName.end()));

    auto pidOpt = atk::findProcessByName(targetName);
    if (!pidOpt) {
        atk::printFail("Target process not found. Is target.exe running?");
        return 1;
    }

    DWORD targetPid = *pidOpt;
    atk::printOk("Found target PID: " + std::to_string(targetPid));
    std::cout << '\n';

    // -----------------------------------------------------------------------
    // Dispatch to the selected attack.
    // -----------------------------------------------------------------------
    bool success = false;

    switch (attackMode) {

        case atk::AttackMode::Terminate:
            success = atk::attackTerminate(targetPid);
            break;

        case atk::AttackMode::Inject: {
            // Resolve payload.dll path relative to attacker.exe.
            wchar_t exePath[MAX_PATH]{};
            GetModuleFileNameW(nullptr, exePath, MAX_PATH);
            std::filesystem::path dllPath =
                std::filesystem::path(exePath).parent_path() / L"payload.dll";

            if (!std::filesystem::exists(dllPath)) {
                atk::printFail("payload.dll not found at: " + dllPath.string());
                atk::printInfo("Build the 'payload' CMake target and ensure payload.dll");
                atk::printInfo("is in the same directory as attacker.exe.");
                return 1;
            }
            success = atk::attackInject(targetPid, dllPath.wstring());
            break;
        }

        case atk::AttackMode::Patch:
            success = atk::attackPatch(targetPid);
            break;

        case atk::AttackMode::Suspend:
            success = atk::attackSuspend(targetPid);
            break;

        case atk::AttackMode::HandleLeak:
            success = atk::attackHandleLeak(targetPid);
            break;

        default:
            atk::printFail("Unhandled attack mode");
            return 1;
    }

    std::cout << '\n';
    if (success) {
        atk::printOk("Attack '" + std::string(atk::modeName(attackMode)) + "' completed.");
    } else {
        atk::printFail("Attack '" + std::string(atk::modeName(attackMode)) + "' failed.");
    }

    return success ? 0 : 1;
}
