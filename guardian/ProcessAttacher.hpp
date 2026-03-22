#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <string>
#include <string_view>

#include "Result.hpp"
#include "WinHandle.hpp"

namespace pg {

// ---------------------------------------------------------------------------
// ProcessAttacher
//
// Locates a target process by name and opens a handle with the minimum
// required access rights. Returns std::expected (aliased as Result) so
// all error handling is explicit and composable.
//
// Access rights rationale:
//   MemoryIntegrityMonitor  needs: PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
//   ModuleWatchdog          needs: PROCESS_QUERY_INFORMATION
//   EtwSessionMonitor       needs: nothing (ETW is out-of-band)
// ---------------------------------------------------------------------------

struct AttachError {
    enum class Kind {
        ProcessNotFound,
        OpenFailed,
        AccessDenied,
    };
    Kind        kind;
    WinError    winErr;
    std::string detail;
};

class ProcessAttacher {
public:
    // Find a process by image name and return its PID.
    static Result<DWORD, AttachError> findByName(std::wstring_view imageName);

    // Open a handle to a known PID with the requested access mask.
    static Result<WinHandle, AttachError> openProcess(DWORD pid, DWORD desiredAccess);

    // Convenience: find by name then open.
    static Result<WinHandle, AttachError> findAndOpen(std::wstring_view imageName,
                                                       DWORD desiredAccess);

    // Launch a new process suspended, returning its handle and PID.
    // The caller is responsible for calling ResumeThread when ready.
    struct SuspendedProcess {
        WinHandle processHandle;
        WinHandle threadHandle;   // main thread -- call ResumeThread on this
        DWORD     pid;
    };
    static Result<SuspendedProcess, AttachError> launchSuspended(
        std::wstring_view exePath);
};

} // namespace pg
