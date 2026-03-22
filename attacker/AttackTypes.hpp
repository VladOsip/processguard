#pragma once
#include <string_view>

namespace atk {

// ---------------------------------------------------------------------------
// AttackMode
//
// Each mode simulates a distinct real-world attack technique.
// The attacker binary accepts a mode name as a CLI argument.
//
// Modes that the guardian SHOULD detect:
//   terminate        - OpenProcess(PROCESS_TERMINATE) + TerminateProcess
//   inject           - LoadLibrary-style DLL injection via CreateRemoteThread
//   patch            - WriteProcessMemory into the .text section
//
// Modes the guardian currently does NOT detect (educational):
//   suspend          - Suspend all threads in the target (freezes it silently)
//   handle-leak      - Open a high-privilege handle and hold it (ETW bait)
//
// All modes print what they are doing step by step so the output is useful
// as a live demo or a recorded walkthrough.
// ---------------------------------------------------------------------------

enum class AttackMode {
    Terminate,      // kill the process outright
    Inject,         // LoadLibrary DLL injection
    Patch,          // WriteProcessMemory .text corruption
    Suspend,        // freeze all threads (guardian does NOT detect this)
    HandleLeak,     // acquire and hold a dangerous handle (ETW detects the open)
    Unknown,
};

inline AttackMode parseMode(std::string_view s) {
    if (s == "terminate")   return AttackMode::Terminate;
    if (s == "inject")      return AttackMode::Inject;
    if (s == "patch")       return AttackMode::Patch;
    if (s == "suspend")     return AttackMode::Suspend;
    if (s == "handle-leak") return AttackMode::HandleLeak;
    return AttackMode::Unknown;
}

inline std::string_view modeName(AttackMode m) {
    switch (m) {
        case AttackMode::Terminate:  return "terminate";
        case AttackMode::Inject:     return "inject";
        case AttackMode::Patch:      return "patch";
        case AttackMode::Suspend:    return "suspend";
        case AttackMode::HandleLeak: return "handle-leak";
        default:                     return "unknown";
    }
}

} // namespace atk
