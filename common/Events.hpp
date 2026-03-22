#pragma once

#include <string>
#include <chrono>
#include <cstdint>

namespace pg {

// ----------------------------------------------------------------------------
// SecurityEvent
//
// The unified event type that all monitor threads post to the EventDispatcher.
// Using a tagged union / enum keeps the dispatch table simple and avoids
// dynamic_cast overhead that you'd get with a polymorphic hierarchy.
// ----------------------------------------------------------------------------

enum class EventType {
    // MemoryIntegrityMonitor
    MemoryRegionModified,

    // ModuleWatchdog
    UnexpectedModuleLoaded,

    // EtwSessionMonitor
    SuspiciousHandleAcquired,
    ProcessTerminationAttempt,

    // HeartbeatMonitor
    ThreadsSuspended,
    HeartbeatRestored,

    // Internal
    MonitorError,
    TargetExited,
};

struct SecurityEvent {
    EventType   type;
    std::string description;
    std::string detail;          // extra context (addresses, module names, etc.)
    DWORD       sourcePid{0};    // PID that triggered the event, if known
    std::chrono::system_clock::time_point timestamp{
        std::chrono::system_clock::now()
    };
};

// Convenience factories so call sites don't have to fill each field manually.
inline SecurityEvent makeMemoryEvent(std::string description, std::string detail = {}) {
    return SecurityEvent{
        .type        = EventType::MemoryRegionModified,
        .description = std::move(description),
        .detail      = std::move(detail),
    };
}

inline SecurityEvent makeModuleEvent(std::string moduleName) {
    return SecurityEvent{
        .type        = EventType::UnexpectedModuleLoaded,
        .description = "Unexpected module loaded into target",
        .detail      = std::move(moduleName),
    };
}

inline SecurityEvent makeHandleEvent(DWORD callerPid, std::string detail = {}) {
    return SecurityEvent{
        .type        = EventType::SuspiciousHandleAcquired,
        .description = "External process acquired handle to target",
        .detail      = std::move(detail),
        .sourcePid   = callerPid,
    };
}

inline SecurityEvent makeErrorEvent(std::string description) {
    return SecurityEvent{
        .type        = EventType::MonitorError,
        .description = std::move(description),
    };
}

inline SecurityEvent makeSuspendEvent(std::string detail) {
    return SecurityEvent{
        .type        = EventType::ThreadsSuspended,
        .description = "Target heartbeat lost — threads likely suspended",
        .detail      = std::move(detail),
    };
}

inline SecurityEvent makeHeartbeatRestoredEvent() {
    return SecurityEvent{
        .type        = EventType::HeartbeatRestored,
        .description = "Target heartbeat resumed — threads no longer suspended",
    };
}

} // namespace pg
