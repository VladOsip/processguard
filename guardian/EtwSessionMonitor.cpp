#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <optional>
#include <vector>

#include "EtwSessionMonitor.hpp"
#include "Logger.hpp"

namespace pg {

// ---------------------------------------------------------------------------
// Static member definitions
// ---------------------------------------------------------------------------

const GUID EtwSessionMonitor::KERNEL_OBJECT_PROVIDER_GUID = {
    0x845B0100, 0xCB7E, 0x4A1E,
    { 0xAB, 0xAB, 0xAD, 0x78, 0xF1, 0x96, 0x51, 0x78 }
};

thread_local EtwSessionMonitor* EtwSessionMonitor::t_instance = nullptr;

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

EtwSessionMonitor::EtwSessionMonitor(DWORD guardedPid, AlertCallback cb)
    : m_guardedPid(guardedPid), m_onAlert(std::move(cb))
{}

EtwSessionMonitor::~EtwSessionMonitor() {
    stop();
}

// ---------------------------------------------------------------------------
// start()
// ---------------------------------------------------------------------------

Result<void, EtwError> EtwSessionMonitor::start() {
    if (auto r = startSession(); !r) return r;
    if (auto r = enableProviderWithPidFilter(); !r) return r;

    EVENT_TRACE_LOGFILEW logFile{};
    logFile.LoggerName          = const_cast<LPWSTR>(SESSION_NAME);
    logFile.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME |
                                   PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = &EtwSessionMonitor::eventRecordCallback;

    m_traceHandle = OpenTraceW(&logFile);
    if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE)
        return std::unexpected(EtwError{ "OpenTrace failed", GetLastError() });

    m_running = true;
    m_consumerThread = std::thread([this] {
        t_instance = this;
        ULONG status = ProcessTrace(&m_traceHandle, 1, nullptr, nullptr);
        if (status != ERROR_SUCCESS && m_running)
            Logger::error("ProcessTrace exited with status {}", status);
    });

    Logger::info("ETW session started, monitoring PID {} with kernel-side PID filter",
                 m_guardedPid);
    return {};
}

// ---------------------------------------------------------------------------
// stop()
// ---------------------------------------------------------------------------

void EtwSessionMonitor::stop() {
    if (!m_running.exchange(false)) return;

    if (m_sessionHandle != INVALID_PROCESSTRACE_HANDLE) {
        constexpr size_t bufSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(SESSION_NAME);
        std::vector<BYTE> buf(bufSize, 0);
        auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());
        props->Wnode.BufferSize   = static_cast<ULONG>(bufSize);
        props->LoggerNameOffset   = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(m_sessionHandle, SESSION_NAME, props,
                      EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    if (m_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(m_traceHandle);
        m_traceHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    if (m_consumerThread.joinable())
        m_consumerThread.join();

    Logger::info("ETW session stopped");
}

// ---------------------------------------------------------------------------
// startSession()
// ---------------------------------------------------------------------------

Result<void, EtwError> EtwSessionMonitor::startSession() {
    constexpr size_t bufSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(SESSION_NAME);
    std::vector<BYTE> buf(bufSize, 0);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());

    auto initProps = [&] {
        std::fill(buf.begin(), buf.end(), 0);
        props->Wnode.BufferSize    = static_cast<ULONG>(bufSize);
        props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        props->Wnode.ClientContext  = 1;
        props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
        props->MinimumBuffers      = 4;
        props->MaximumBuffers      = 8;
        props->BufferSize          = 64;
        props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
    };

    initProps();
    ControlTraceW(0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);

    initProps();
    ULONG status = StartTraceW(&m_sessionHandle, SESSION_NAME, props);
    if (status != ERROR_SUCCESS)
        return std::unexpected(EtwError{
            "StartTrace failed -- are you running as Administrator?", status
        });

    return {};
}

// ---------------------------------------------------------------------------
// enableProviderWithPidFilter()
//
// Enables the Kernel-Object provider with a PID filter so the kernel only
// emits events where the target of the OpenProcess call is our guarded PID.
//
// Without this filter, every OpenProcess call system-wide is delivered to
// our consumer callback, creating unnecessary CPU overhead and risking
// buffer overflow (ETW silently drops events when buffers are full).
//
// EVENT_FILTER_TYPE_PID is documented in the Windows SDK as a supported
// filter type for user-mode ETW providers. It causes the kernel to evaluate
// the filter before writing the event into the session buffer.
//
// The filter payload is a DWORD array of PIDs to include.
// ---------------------------------------------------------------------------

Result<void, EtwError> EtwSessionMonitor::enableProviderWithPidFilter() {
    // Build the PID filter descriptor.
    DWORD pidFilter = m_guardedPid;

    EVENT_FILTER_DESCRIPTOR filterDesc{};
    filterDesc.Ptr  = reinterpret_cast<ULONGLONG>(&pidFilter);
    filterDesc.Size = sizeof(DWORD);
    filterDesc.Type = EVENT_FILTER_TYPE_PID;

    ENABLE_TRACE_PARAMETERS params{};
    params.Version                              = ENABLE_TRACE_PARAMETERS_VERSION_2;
    params.EnableProperty                       = 0;
    params.ControlFlags                         = 0;
    params.SourceId                             = GUID_NULL;
    params.EnableFilterDesc                     = &filterDesc;
    params.FilterDescCount                      = 1;

    ULONG status = EnableTraceEx2(
        m_sessionHandle,
        &KERNEL_OBJECT_PROVIDER_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0xFFFFFFFFFFFFFFFF,
        0,
        0,
        &params
    );

    if (status != ERROR_SUCCESS) {
        // PID filtering is a best-effort enhancement. If it fails (e.g. on
        // older Windows), fall back to enabling the provider without a filter
        // and doing per-event PID checks in the callback instead.
        Logger::warn("ETW PID filter not supported (status {}), "
                     "falling back to callback-side filtering", status);

        status = EnableTraceEx2(
            m_sessionHandle,
            &KERNEL_OBJECT_PROVIDER_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            0xFFFFFFFFFFFFFFFF,
            0, 0, nullptr
        );

        if (status != ERROR_SUCCESS)
            return std::unexpected(EtwError{
                "EnableTraceEx2 failed for Kernel-Object provider", status
            });
    }
    else {
        Logger::info("Kernel-Object ETW provider enabled with kernel-side PID filter ({})",
                     m_guardedPid);
    }

    return {};
}

// ---------------------------------------------------------------------------
// eventRecordCallback() -- static, called by ProcessTrace
// ---------------------------------------------------------------------------

void WINAPI EtwSessionMonitor::eventRecordCallback(PEVENT_RECORD pEvent) {
    if (t_instance)
        t_instance->handleEvent(pEvent);
}

// ---------------------------------------------------------------------------
// getUlongProperty()
//
// TDH helper: given a decoded TRACE_EVENT_INFO and a property name, returns
// the ULONG value of that property from the event's UserData.
//
// Why TDH instead of hardcoded offsets:
//   The raw UserData blob layout depends on the provider schema, which can
//   differ between Windows versions. TDH reads the schema at runtime from
//   the provider registration and gives us field names, types, and offsets.
//   This is the documented, stable way to parse ETW events.
//
// Steps:
//   1. Find the named property in pInfo->EventPropertyInfoArray[].
//   2. Use TdhGetProperty to extract the value by property descriptor.
//      TdhGetProperty handles endianness, length, and type for us.
// ---------------------------------------------------------------------------

std::optional<ULONG>
EtwSessionMonitor::getUlongProperty(PEVENT_RECORD pEvent,
                                     PTRACE_EVENT_INFO pInfo,
                                     std::wstring_view propertyName) {
    // Walk the property array looking for a matching name.
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; ++i) {
        const auto& prop = pInfo->EventPropertyInfoArray[i];
        const wchar_t* name = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const BYTE*>(pInfo) + prop.NameOffset);

        if (propertyName != name) continue;

        // Found the property. Use TdhGetProperty to extract the value.
        PROPERTY_DATA_DESCRIPTOR descriptor{};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
        descriptor.ArrayIndex   = ULONG_MAX;  // not an array element

        ULONG value{};
        ULONG bufSize = sizeof(value);
        ULONG status = TdhGetProperty(pEvent, 0, nullptr,
                                       1, &descriptor,
                                       bufSize,
                                       reinterpret_cast<PBYTE>(&value));
        if (status == ERROR_SUCCESS)
            return value;

        // Property exists but TdhGetProperty failed (e.g. wrong size).
        return std::nullopt;
    }

    return std::nullopt;  // property name not found
}

// ---------------------------------------------------------------------------
// handleEvent()
//
// Uses TDH to decode the event and extract fields by name, replacing the
// previous hardcoded byte-offset reads.
//
// Event ID 1 in the Kernel-Object provider = OpenProcess.
// We look for three properties:
//   "TargetProcessId"   -- the process being opened
//   "DesiredAccess"     -- the access mask requested
//   "CallingProcessId"  -- who called OpenProcess
// ---------------------------------------------------------------------------

void EtwSessionMonitor::handleEvent(PEVENT_RECORD pEvent) {
    if (!m_running) return;
    if (pEvent->EventHeader.EventDescriptor.Id != 1) return;

    // Retrieve the TRACE_EVENT_INFO for this event via TDH.
    // TdhGetEventInformation fills a variable-length struct; we first call
    // with size 0 to discover the required buffer size, then allocate and call again.
    ULONG infoSize{};
    TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &infoSize);
    if (infoSize == 0) return;

    std::vector<BYTE> infoBuf(infoSize);
    auto* pInfo = reinterpret_cast<TRACE_EVENT_INFO*>(infoBuf.data());

    if (TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &infoSize) != ERROR_SUCCESS)
        return;

    // Extract the three fields we care about.
    const auto targetPid     = getUlongProperty(pEvent, pInfo, L"TargetProcessId");
    const auto desiredAccess = getUlongProperty(pEvent, pInfo, L"DesiredAccess");
    const auto callerPid     = getUlongProperty(pEvent, pInfo, L"CallingProcessId");

    if (!targetPid || !desiredAccess || !callerPid) {
        // Schema doesn't have the fields we expect -- provider version mismatch.
        Logger::debug("ETW: OpenProcess event missing expected properties");
        return;
    }

    // Even with kernel-side PID filtering we double-check here, because the
    // filter is best-effort (may have fallen back to no filter).
    if (*targetPid != m_guardedPid) return;
    if (*callerPid == GetCurrentProcessId()) return;  // ignore our own guardian

    constexpr DWORD DANGEROUS_ACCESS =
        PROCESS_TERMINATE | PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;

    if (*desiredAccess & DANGEROUS_ACCESS) {
        const std::string detail = std::format(
            "Caller PID: {} | Access mask: 0x{:08X}", *callerPid, *desiredAccess);
        Logger::error("Suspicious handle acquisition detected! {}", detail);
        m_onAlert(makeHandleEvent(*callerPid, detail));
    }
}

} // namespace pg
