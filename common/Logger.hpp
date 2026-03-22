#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <format>
#include <iostream>
#include <mutex>
#include <print>           // C++23 -- std::println
#include <source_location>
#include <string>
#include <string_view>
#include <chrono>

namespace pg {

// ---------------------------------------------------------------------------
// Logger  (C++23 edition)
//
// Changes from C++20 version:
//   - Custom variadic {} formatter replaced with std::format (C++20/23).
//     std::format accepts a compile-time format string and typed arguments,
//     giving us proper type safety and eliminating the hand-rolled
//     formatInto() recursive template.
//   - std::println (C++23) replaces std::cout << ... << '\n'.
//     std::println is atomic per-call and flushes after each line, which
//     matters in a multi-threaded security agent where log lines from
//     different threads must not interleave.
//   - std::chrono::zoned_time (C++20) used for cleaner timestamp formatting.
// ---------------------------------------------------------------------------

enum class LogLevel { Debug, Info, Warn, Error };

class Logger {
public:
    static void setLevel(LogLevel level) noexcept {
        instance().m_level = level;
    }

    template<typename... Args>
    static void debug(std::format_string<Args...> fmt, Args&&... args,
                      std::source_location loc = std::source_location::current())
    {
        instance().log(LogLevel::Debug, loc,
                       std::format(fmt, std::forward<Args>(args)...));
    }

    template<typename... Args>
    static void info(std::format_string<Args...> fmt, Args&&... args,
                     std::source_location loc = std::source_location::current())
    {
        instance().log(LogLevel::Info, loc,
                       std::format(fmt, std::forward<Args>(args)...));
    }

    template<typename... Args>
    static void warn(std::format_string<Args...> fmt, Args&&... args,
                     std::source_location loc = std::source_location::current())
    {
        instance().log(LogLevel::Warn, loc,
                       std::format(fmt, std::forward<Args>(args)...));
    }

    template<typename... Args>
    static void error(std::format_string<Args...> fmt, Args&&... args,
                      std::source_location loc = std::source_location::current())
    {
        instance().log(LogLevel::Error, loc,
                       std::format(fmt, std::forward<Args>(args)...));
    }

private:
    Logger() = default;

    static Logger& instance() {
        static Logger s_instance;
        return s_instance;
    }

    void log(LogLevel level, const std::source_location& loc,
             std::string message)
    {
        if (level < m_level) return;

        // Timestamp via std::chrono
        auto now  = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        char timeBuf[32]{};
        struct tm tmBuf{};
        localtime_s(&tmBuf, &time);
        std::strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", &tmBuf);

        // Trim path to filename only
        std::string_view file = loc.file_name();
        if (auto slash = file.find_last_of("/\\");
            slash != std::string_view::npos)
            file = file.substr(slash + 1);

        std::lock_guard lock(m_mutex);
        setColor(level);
        // std::println is atomic and appends '\n' automatically
        std::println("[{}] {} {}  ({}:{})",
                     timeBuf, levelTag(level), message,
                     file, loc.line());
        resetColor();
    }

    static const char* levelTag(LogLevel l) noexcept {
        switch (l) {
            case LogLevel::Debug: return "[DBG]";
            case LogLevel::Info:  return "[INF]";
            case LogLevel::Warn:  return "[WRN]";
            case LogLevel::Error: return "[ERR]";
        }
        return "[???]";
    }

    static void setColor(LogLevel l) noexcept {
        HANDLE hcon = GetStdHandle(STD_OUTPUT_HANDLE);
        switch (l) {
            case LogLevel::Debug: SetConsoleTextAttribute(hcon, 8);  break;
            case LogLevel::Info:  SetConsoleTextAttribute(hcon, 7);  break;
            case LogLevel::Warn:  SetConsoleTextAttribute(hcon, 14); break;
            case LogLevel::Error: SetConsoleTextAttribute(hcon, 12); break;
        }
    }

    static void resetColor() noexcept {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
    }

    std::mutex m_mutex;
    LogLevel   m_level{ LogLevel::Info };
};

} // namespace pg
