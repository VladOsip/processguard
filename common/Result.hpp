#pragma once

// ---------------------------------------------------------------------------
// Result.hpp  (C++23 edition)
//
// In C++20 we hand-rolled a monadic Result<T,E> type modelled on Rust.
// C++23 ships std::expected<T,E> in <expected>, which provides:
//   - .value(), .error(), .has_value(), operator bool
//   - .and_then(f)   -- chain a function returning expected, propagate error
//   - .transform(f)  -- map the value, propagate error   (was .map())
//   - .or_else(f)    -- transform the error              (was .map_err())
//   - .value_or(d)   -- return value or default
//
// All call sites in this project now use std::expected directly.
// The old Result<void,E> specialisation is replaced by std::expected<void,E>
// which std::expected supports natively.
//
// WinError lives here because every subsystem that returns errors uses it.
// ---------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <expected>
#include <string>

namespace pg {

// Re-export std::expected as Result so all existing call sites keep compiling.
template<typename T, typename E>
using Result = std::expected<T, E>;

// Convenience wrappers that mirror the old Result::Ok / Result::Err syntax.
// std::expected uses std::unexpected for the error case.
template<typename T, typename E>
[[nodiscard]] constexpr std::expected<T, E> MakeOk(T val) {
    return std::expected<T, E>{ std::move(val) };
}

template<typename E>
[[nodiscard]] constexpr auto MakeErr(E err) {
    return std::unexpected<E>{ std::move(err) };
}

// ---------------------------------------------------------------------------
// WinError -- thin wrapper around a Win32 DWORD error code + context string.
// ---------------------------------------------------------------------------
struct WinError {
    DWORD       code{ 0 };
    std::string context;

    WinError() = default;
    WinError(DWORD c, std::string ctx) : code(c), context(std::move(ctx)) {}

    static WinError fromLastError(std::string ctx) {
        return WinError{ ::GetLastError(), std::move(ctx) };
    }

    std::string message() const;
};

} // namespace pg
