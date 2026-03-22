#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "Result.hpp"
#include "Events.hpp"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace pg {

// ---------------------------------------------------------------------------
// EtwSessionMonitor  (C++23 edition)
//
// Changes from C++20 version:
//
//   TDH field lookup (version-robust event parsing):
//     Instead of reading event UserData at hardcoded byte offsets, we use
//     TdhGetEventInformation to retrieve the provider schema for each event,
//     then look up fields by name ("TargetProcessId", "DesiredAccess",
//     "CallingProcessId"). This is correct across all Windows versions.
//     The hardcoded-offset approach silently breaks on schema changes.
//
//   Provider-side PID filtering (eliminates event flood):
//     EnableTraceEx2 now passes an EVENT_FILTER_DESCRIPTOR with type
//     EVENT_FILTER_TYPE_PID containing only m_guardedPid. The kernel
//     checks this filter before writing events into the ETW buffer, so
//     only events targeting our specific process are delivered.
//     This eliminates the system-wide flood of OpenProcess events that
//     previously required per-event discard in the callback, and prevents
//     event buffer overflow under load.
//
//   std::expected replaces hand-rolled Result throughout.
// ---------------------------------------------------------------------------

struct EtwError {
    std::string message;
    ULONG       status{ 0 };
};

class EtwSessionMonitor {
public:
    using AlertCallback = std::function<void(SecurityEvent)>;

    EtwSessionMonitor(DWORD guardedPid, AlertCallback cb);
    ~EtwSessionMonitor();

    EtwSessionMonitor(const EtwSessionMonitor&)            = delete;
    EtwSessionMonitor& operator=(const EtwSessionMonitor&) = delete;

    Result<void, EtwError> start();
    void stop();

private:
    static void WINAPI eventRecordCallback(PEVENT_RECORD pEvent);
    void handleEvent(PEVENT_RECORD pEvent);

    // TDH helpers
    // Returns the ULONG value of a named property in the event, or nullopt.
    static std::optional<ULONG> getUlongProperty(PEVENT_RECORD pEvent,
                                                   PTRACE_EVENT_INFO pInfo,
                                                   std::wstring_view propertyName);

    Result<void, EtwError> startSession();
    Result<void, EtwError> enableProviderWithPidFilter();

    static constexpr wchar_t SESSION_NAME[] = L"ProcessGuardEtwSession";

    // Microsoft-Windows-Kernel-Object  {845B0100-CB7E-4A1E-ABAB-AD78F1965178}
    static const GUID KERNEL_OBJECT_PROVIDER_GUID;

    DWORD         m_guardedPid;
    AlertCallback m_onAlert;

    TRACEHANDLE        m_sessionHandle{ INVALID_PROCESSTRACE_HANDLE };
    TRACEHANDLE        m_traceHandle{ INVALID_PROCESSTRACE_HANDLE };

    std::thread        m_consumerThread;
    std::atomic<bool>  m_running{ false };

    static thread_local EtwSessionMonitor* t_instance;
};

} // namespace pg
