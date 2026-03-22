#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "Result.hpp"

namespace pg {

std::string WinError::message() const {
    if (code == 0) return context.empty() ? "Success" : context;

    char* buf = nullptr;
    DWORD len = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM     |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buf),
        0,
        nullptr
    );

    std::string msg;
    if (len && buf) {
        msg = buf;
        LocalFree(buf);
        // Strip trailing newline that FormatMessage adds.
        while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r'))
            msg.pop_back();
    } else {
        msg = "Unknown error";
    }

    if (!context.empty())
        return context + ": " + msg + " (0x" + std::to_string(code) + ")";
    return msg + " (0x" + std::to_string(code) + ")";
}

} // namespace pg
