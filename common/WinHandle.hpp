#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <memory>
#include <utility>

namespace pg {

// ----------------------------------------------------------------------------
// WinHandle
//
// RAII wrapper around a Windows HANDLE. Automatically calls CloseHandle on
// destruction. Non-copyable, movable.
//
// Why this matters in a security context:
//   Handle leaks are a real problem in long-running security agents. A leaked
//   process handle with PROCESS_ALL_ACCESS is a privilege escalation vector —
//   an attacker can inherit or duplicate the handle. By wrapping every handle
//   in RAII, we guarantee the handle is closed at the earliest possible moment.
//
// Usage:
//   WinHandle h(OpenProcess(PROCESS_VM_READ, FALSE, pid));
//   if (!h) { /* open failed */ }
//   ReadProcessMemory(h.get(), ...);
//   // h is closed automatically when it goes out of scope
// ----------------------------------------------------------------------------

class WinHandle {
public:
    // Construct from a raw HANDLE (may be NULL or INVALID_HANDLE_VALUE).
    explicit WinHandle(HANDLE h = nullptr) noexcept
        : m_handle(normalize(h), &WinHandle::close)
    {}

    // Move-only — handles must not be duplicated accidentally.
    WinHandle(const WinHandle&)            = delete;
    WinHandle& operator=(const WinHandle&) = delete;

    WinHandle(WinHandle&&)            noexcept = default;
    WinHandle& operator=(WinHandle&&) noexcept = default;

    // True if the handle is valid (non-null, non-INVALID_HANDLE_VALUE).
    [[nodiscard]] bool valid() const noexcept {
        return m_handle != nullptr;
    }
    explicit operator bool() const noexcept { return valid(); }

    // Access the raw handle. Does not release ownership.
    [[nodiscard]] HANDLE get() const noexcept {
        return m_handle.get();
    }

    // Release ownership and return the raw handle.
    // Caller is responsible for CloseHandle.
    [[nodiscard]] HANDLE release() noexcept {
        return m_handle.release();
    }

    // Explicitly close before going out of scope.
    void reset(HANDLE h = nullptr) noexcept {
        m_handle.reset(normalize(h));
    }

private:
    static void close(HANDLE h) noexcept {
        if (h) ::CloseHandle(h);
    }

    // Treat INVALID_HANDLE_VALUE as null so unique_ptr's null check works.
    static HANDLE normalize(HANDLE h) noexcept {
        return (h == INVALID_HANDLE_VALUE) ? nullptr : h;
    }

    struct HandleDeleter {
        using pointer = HANDLE;
        void operator()(HANDLE h) const noexcept { WinHandle::close(h); }
    };

    std::unique_ptr<void, HandleDeleter> m_handle;
};

} // namespace pg
