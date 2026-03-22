#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include "ProcessAttacher.hpp"
#include "Logger.hpp"

namespace pg {

Result<DWORD, AttachError> ProcessAttacher::findByName(std::wstring_view imageName) {
    WinHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot)
        return std::unexpected(AttachError{
            .kind   = AttachError::Kind::OpenFailed,
            .winErr = WinError::fromLastError("CreateToolhelp32Snapshot"),
        });

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (!Process32FirstW(snapshot.get(), &entry))
        return std::unexpected(AttachError{
            .kind   = AttachError::Kind::ProcessNotFound,
            .winErr = WinError::fromLastError("Process32FirstW"),
        });

    do {
        if (std::wstring_view(entry.szExeFile) == imageName) {
            Logger::info("Found target '{}' with PID {}",
                         std::string(imageName.begin(), imageName.end()),
                         entry.th32ProcessID);
            return entry.th32ProcessID;
        }
    } while (Process32NextW(snapshot.get(), &entry));

    return std::unexpected(AttachError{
        .kind   = AttachError::Kind::ProcessNotFound,
        .detail = std::string(imageName.begin(), imageName.end()) + " not found",
    });
}

Result<WinHandle, AttachError> ProcessAttacher::openProcess(DWORD pid,
                                                              DWORD desiredAccess) {
    HANDLE h = ::OpenProcess(desiredAccess, FALSE, pid);
    if (!h) {
        DWORD err  = GetLastError();
        auto  kind = (err == ERROR_ACCESS_DENIED)
                     ? AttachError::Kind::AccessDenied
                     : AttachError::Kind::OpenFailed;
        return std::unexpected(AttachError{
            .kind   = kind,
            .winErr = WinError{ err, "OpenProcess" },
        });
    }
    Logger::info("Opened handle to PID {} with access mask 0x{:08X}", pid, desiredAccess);
    return WinHandle(h);
}

Result<WinHandle, AttachError> ProcessAttacher::findAndOpen(std::wstring_view imageName,
                                                              DWORD desiredAccess) {
    // std::expected::and_then chains two expected-returning functions.
    // If findByName returns an error, and_then propagates it unchanged
    // without calling the lambda -- identical to the old Result::and_then.
    return findByName(imageName)
        .and_then([desiredAccess](DWORD pid) {
            return openProcess(pid, desiredAccess);
        });
}

// ---------------------------------------------------------------------------
// launchSuspended()
//
// Launches an executable with CREATE_SUSPENDED so the guardian can take its
// baseline snapshot before any of the target's code runs.
//
// The caller receives the process handle, the main thread handle, and the PID.
// After all monitors are initialised, call ResumeThread(result.threadHandle)
// to let the target start executing.
//
// This eliminates the initialization race: there is no window between
// "target starts" and "guardian is watching" because the target hasn't
// executed a single instruction before the baseline is taken.
// ---------------------------------------------------------------------------
Result<ProcessAttacher::SuspendedProcess, AttachError>
ProcessAttacher::launchSuspended(std::wstring_view exePath) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::wstring path(exePath);

    BOOL ok = CreateProcessW(
        path.c_str(),
        nullptr,            // command line
        nullptr,            // process security attributes
        nullptr,            // thread security attributes
        FALSE,              // don't inherit handles
        CREATE_SUSPENDED,   // key flag -- main thread created but not scheduled
        nullptr,            // inherit environment
        nullptr,            // inherit working directory
        &si, &pi
    );

    if (!ok)
        return std::unexpected(AttachError{
            .kind   = AttachError::Kind::OpenFailed,
            .winErr = WinError::fromLastError("CreateProcessW(CREATE_SUSPENDED)"),
            .detail = std::string(exePath.begin(), exePath.end()),
        });

    Logger::info("Launched '{}' suspended, PID {}",
                 std::string(exePath.begin(), exePath.end()), pi.dwProcessId);

    return SuspendedProcess{
        .processHandle = WinHandle(pi.hProcess),
        .threadHandle  = WinHandle(pi.hThread),
        .pid           = pi.dwProcessId,
    };
}

} // namespace pg
