// payload.cpp
//
// This is the DLL that the 'inject' attack mode loads into the target process.
// It is deliberately benign — it just shows a message box and logs to the
// debugger output so the effect is visible.
//
// In a real attack this DLL would contain shellcode, a reverse shell,
// keylogger hooks, or whatever the attacker wants to run in the target's
// context and with the target's privileges.
//
// Build separately as a DLL:
//   In CMake this is the 'payload' target (see CMakeLists.txt).
//   The output payload.dll must be in the same directory as attacker.exe.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Disable DLL_THREAD_ATTACH/DETACH notifications — we don't need them.
        DisableThreadLibraryCalls(hInst);

        // Get our own module path so the message box is informative.
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(hInst, path, MAX_PATH);

        // Get the host process name.
        wchar_t hostPath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, hostPath, MAX_PATH);

        std::wstring msg = L"payload.dll has been injected!\n\n"
                           L"DLL path:  " + std::wstring(path) + L"\n"
                           L"Host process: " + std::wstring(hostPath) + L"\n"
                           L"Host PID: " + std::to_wstring(GetCurrentProcessId());

        // OutputDebugString is visible in DebugView or a debugger.
        OutputDebugStringW((msg + L"\n").c_str());

        // MessageBox makes the injection undeniable in a live demo.
        // Runs on a new thread so DllMain returns quickly.
        // (Calling MessageBox directly from DllMain is technically illegal
        //  due to loader lock, but it works in practice for demo purposes.)
        CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
            auto* wstr = static_cast<std::wstring*>(param);
            MessageBoxW(nullptr, wstr->c_str(), L"ProcessGuard: Injection Detected!",
                        MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
            delete wstr;
            return 0;
        }, new std::wstring(msg), 0, nullptr);
    }
    return TRUE;
}
