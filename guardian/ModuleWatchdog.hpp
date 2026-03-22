#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <functional>
#include <string>
#include <unordered_set>

#include "Result.hpp"
#include "Events.hpp"

namespace pg {

// ---------------------------------------------------------------------------
// ModuleWatchdog  (C++23 edition)
//
// Changes from C++20 version:
//   - Accepts is32BitTarget flag so it uses EnumProcessModulesEx with
//     LIST_MODULES_32BIT for WOW64 targets (a plain 64-bit guardian calling
//     EnumProcessModules on a 32-bit target may receive an incomplete list).
//   - std::unexpected replaces Result::Err throughout.
//   - enumerateModules() is now const.
// ---------------------------------------------------------------------------

struct WatchdogError {
    std::string message;
    DWORD       winCode{ 0 };
};

class ModuleWatchdog {
public:
    using AlertCallback = std::function<void(SecurityEvent)>;

    explicit ModuleWatchdog(HANDLE hProcess, AlertCallback cb,
                             bool is32BitTarget = false);

    Result<void, WatchdogError> initialize();
    void poll();

private:
    using ModuleSet = std::unordered_set<std::wstring>;

    Result<ModuleSet, WatchdogError> enumerateModules() const;

    HANDLE        m_hProcess;
    AlertCallback m_onAlert;
    bool          m_is32BitTarget;
    ModuleSet     m_whitelist;
};

} // namespace pg
