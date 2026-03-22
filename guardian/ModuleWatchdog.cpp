#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

#include "ModuleWatchdog.hpp"
#include "Logger.hpp"

#pragma comment(lib, "psapi.lib")

namespace pg {

ModuleWatchdog::ModuleWatchdog(HANDLE hProcess, AlertCallback cb,
                                bool is32BitTarget)
    : m_hProcess(hProcess)
    , m_onAlert(std::move(cb))
    , m_is32BitTarget(is32BitTarget)
{}

Result<void, WatchdogError> ModuleWatchdog::initialize() {
    auto result = enumerateModules();
    if (!result)
        return std::unexpected(result.error());

    m_whitelist = std::move(*result);
    Logger::info("ModuleWatchdog: {} module(s) whitelisted", m_whitelist.size());
    for (const auto& mod : m_whitelist)
        Logger::debug("  [whitelisted] {}", std::string(mod.begin(), mod.end()));

    return {};
}

void ModuleWatchdog::poll() {
    auto result = enumerateModules();
    if (!result) {
        m_onAlert(makeErrorEvent(
            "ModuleWatchdog: EnumProcessModulesEx failed: " + result.error().message));
        return;
    }

    for (const auto& mod : *result) {
        if (!m_whitelist.contains(mod)) {
            std::string name(mod.begin(), mod.end());
            Logger::error("Unexpected module detected: {}", name);
            m_onAlert(makeModuleEvent(name));
            m_whitelist.insert(mod);  // don't re-alert for the same module
        }
    }
}

// ---------------------------------------------------------------------------
// enumerateModules()
//
// Uses EnumProcessModulesEx rather than plain EnumProcessModules so that
// we correctly enumerate modules in a 32-bit (WOW64) target from a 64-bit
// guardian process.
//
//   LIST_MODULES_32BIT  -- enumerate the WOW64 module list (32-bit target)
//   LIST_MODULES_64BIT  -- enumerate the native module list (64-bit target)
//   LIST_MODULES_ALL    -- both (returns dupes on 64-bit; fine for a whitelist)
//
// We use the full path (not just filename) as the key to prevent an attacker
// from loading a malicious ntdll.dll from a different directory and passing
// a name-only check.
// ---------------------------------------------------------------------------

Result<ModuleWatchdog::ModuleSet, WatchdogError>
ModuleWatchdog::enumerateModules() const {
    const DWORD filter = m_is32BitTarget ? LIST_MODULES_32BIT
                                         : LIST_MODULES_64BIT;

    DWORD needed{};
    EnumProcessModulesEx(m_hProcess, nullptr, 0, &needed, filter);
    if (needed == 0)
        return std::unexpected(WatchdogError{
            "EnumProcessModulesEx returned 0 size", GetLastError()
        });

    std::vector<HMODULE> mods(needed / sizeof(HMODULE));
    if (!EnumProcessModulesEx(m_hProcess, mods.data(),
                               static_cast<DWORD>(mods.size() * sizeof(HMODULE)),
                               &needed, filter))
        return std::unexpected(WatchdogError{
            "EnumProcessModulesEx failed", GetLastError()
        });

    ModuleSet set;
    for (auto hMod : mods) {
        wchar_t path[MAX_PATH]{};
        if (GetModuleFileNameExW(m_hProcess, hMod, path, MAX_PATH))
            set.insert(path);
    }

    return set;
}

} // namespace pg
