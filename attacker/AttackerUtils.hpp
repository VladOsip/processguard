#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <optional>

namespace atk {

// ---------------------------------------------------------------------------
// Console colour helpers — make the attacker output visually distinct from
// the guardian's output so a side-by-side demo is easy to read.
// ---------------------------------------------------------------------------

inline void printStep(std::string_view msg) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11); // cyan
    std::cout << "[*] " << msg << '\n';
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
}

inline void printOk(std::string_view msg) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10); // green
    std::cout << "[+] " << msg << '\n';
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
}

inline void printFail(std::string_view msg) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12); // red
    std::cout << "[-] " << msg << '\n';
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
}

inline void printWarn(std::string_view msg) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14); // yellow
    std::cout << "[!] " << msg << '\n';
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
}

inline void printInfo(std::string_view msg) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7); // white
    std::cout << "    " << msg << '\n';
}

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------

// Find a process by image name, return its PID.
inline std::optional<DWORD> findProcessByName(std::wstring_view name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return std::nullopt;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    std::optional<DWORD> result;
    if (Process32FirstW(snap, &entry)) {
        do {
            if (std::wstring_view(entry.szExeFile) == name) {
                result = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }

    CloseHandle(snap);
    return result;
}

// Enumerate all thread IDs belonging to a process.
inline std::vector<DWORD> getProcessThreadIds(DWORD pid) {
    std::vector<DWORD> tids;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return tids;

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);

    if (Thread32First(snap, &entry)) {
        do {
            if (entry.th32OwnerProcessID == pid) {
                tids.push_back(entry.th32ThreadID);
            }
        } while (Thread32Next(snap, &entry));
    }

    CloseHandle(snap);
    return tids;
}

// Format a Win32 error code as a human-readable string.
inline std::string formatError(DWORD code) {
    char* buf = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                   FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, 0, reinterpret_cast<LPSTR>(&buf), 0, nullptr);
    std::string msg = buf ? buf : "Unknown error";
    if (buf) LocalFree(buf);
    while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r'))
        msg.pop_back();
    return msg + " (" + std::to_string(code) + ")";
}

} // namespace atk
