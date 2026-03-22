# ProcessGuard

A Windows process integrity monitor written in C++23. ProcessGuard attaches to a target process and continuously monitors it for a set of common attack techniques, raising alerts when tampering is detected.

A companion attacker binary is included for live demonstration.

---

## Overview

ProcessGuard runs as a privileged guardian process alongside a target it is protecting. It takes a baseline snapshot of the target at startup, then runs four independent monitors concurrently. Each monitor watches for a different class of attack and reports to a central event dispatcher when something suspicious is detected.

Detection is user-mode only. The guardian cannot prevent attacks — it can only observe and alert. See [Limitations](#limitations) for the architectural reasons behind this ceiling.

---

## Architecture

```
ProcessGuard/
├── common/
│   ├── Result.hpp              # std::expected<T,E> alias + WinError
│   ├── WinHandle.hpp           # RAII wrapper around Windows HANDLE
│   ├── Logger.hpp              # Thread-safe logger (std::format + std::println)
│   ├── Events.hpp              # SecurityEvent types
│   └── WinError.cpp
│
├── guardian/
│   ├── ProcessAttacher         # Find / open / launch-suspended target
│   ├── MemoryIntegrityMonitor  # PE parsing (32+64-bit) + BCrypt SHA-256 hashing
│   ├── ModuleWatchdog          # DLL injection detection (EnumProcessModulesEx)
│   ├── EtwSessionMonitor       # ETW with TDH field lookup + PID filter
│   ├── HeartbeatMonitor        # Named pipe heartbeat — detects thread suspension
│   ├── EventDispatcher         # Thread-safe event bus (std::flat_map)
│   ├── GuardianOrchestrator    # Wires everything together; attach or launch mode
│   └── main.cpp
│
├── target/
│   └── main.cpp                # Heartbeat sender + tick loop
│
└── attacker/
    ├── AttackTypes.hpp
    ├── AttackerUtils.hpp
    ├── Attacks.hpp             # Five attack implementations
    ├── payload.cpp             # Benign injectable DLL
    └── main.cpp
```

### Monitors

| Monitor | What it detects | Mechanism | Latency |
|---|---|---|---|
| `MemoryIntegrityMonitor` | Writes to executable (`.text`) sections | BCrypt SHA-256 hash compared against baseline on each poll | ~1s (poll interval) |
| `ModuleWatchdog` | DLL injection via `LoadLibrary` | `EnumProcessModulesEx` diff against baseline module list | ~1s (poll interval) |
| `EtwSessionMonitor` | Dangerous handle acquisitions; termination attempts | ETW `Microsoft-Windows-Kernel-Object` provider with kernel-side PID filter | Near-immediate |
| `HeartbeatMonitor` | Thread suspension | Named pipe silence exceeding threshold; target pushes beats every 500ms | ~2s (silence threshold) |

### Startup Modes

**Attach mode** — the guardian finds an already-running target by image name and opens a handle to it.

**Launch mode** — the guardian spawns the target with `CREATE_SUSPENDED`, takes all baseline snapshots before the target's first instruction executes, then resumes it. This eliminates the initialisation race that exists in attach mode: an attacker cannot act between target startup and guardian baseline because the target has not started yet.

---

## Requirements

- Windows 10 or later (64-bit)
- Visual Studio 2022 17.6+ with MSVC and C++23 support (`/std:c++latest`)
- CMake 3.20+
- Administrator privileges at runtime (required for ETW session creation)

---

## Building

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Output binaries:

| Binary | Description |
|---|---|
| `guardian.exe` | The monitor process |
| `target.exe` | The demo process being protected |
| `attacker.exe` | Attack simulator |
| `payload.dll` | Benign injectable DLL used by the `inject` attack |

---

## Usage

### Attach mode

```
# Terminal 1 — start the target
.\build\Release\target.exe

# Terminal 2 (Administrator) — attach the guardian
.\build\Release\guardian.exe target.exe 1000
```

Arguments: `guardian.exe <target-image-name> <poll-interval-ms>`

### Launch mode

```
# Terminal 1 (Administrator) — guardian launches and protects from the start
.\build\Release\guardian.exe target.exe 1000 --launch .\build\Release\target.exe
```

The guardian creates the target suspended, takes all baselines, then resumes it. There is no window during which an attacker could act before the guardian is watching.

---

## Attack Demonstrations

With the guardian running, execute any of the following from a third terminal:

```
.\build\Release\attacker.exe <mode> [target-image-name]
```

| Mode | Technique | Detected | Detection mechanism | Latency |
|---|---|---|---|---|
| `terminate` | `TerminateProcess` | ✅ | ETW — handle acquisition | Near-immediate |
| `inject` | `CreateRemoteThread(LoadLibraryW)` | ✅ | `ModuleWatchdog` | ~1s |
| `patch` | `WriteProcessMemory` into `.text` | ✅ | `MemoryIntegrityMonitor` | ~1s |
| `suspend` | `SuspendThread` on all threads | ✅ | `HeartbeatMonitor` | ~2s |
| `handle-leak` | Hold `PROCESS_ALL_ACCESS` handle open | ✅ | ETW — handle acquisition | Near-immediate |

The attacker binary prints annotated step-by-step output describing what each technique does, so it can be used as a live walkthrough alongside the guardian's alerts.

---

## Limitations

These are user-mode architectural constraints, not implementation gaps. Resolving them requires a kernel-mode driver.

| Limitation | Detail |
|---|---|
| Detection without prevention | ETW notifies after a handle has been granted. Only `ObRegisterCallbacks` (kernel) can intercept and strip access rights before the handle is returned to the caller. |
| Poll-and-restore attack | An attacker can patch memory, execute a payload, and restore original bytes within the poll interval. Closing this window requires kernel page-write callbacks or HVCI. |
| Manual DLL mapping | Bypasses `ModuleWatchdog` — no `LoadLibrary` call means no module list entry. Detection requires VAD (Virtual Address Descriptor) scanning in a kernel driver. |
| Kernel-mode attacker | A kernel-mode attacker can disable or bypass all user-mode monitoring entirely. |
| ETW buffer flush lag | ETW events are buffered. Detection is near-immediate but not instantaneous. |
| Short suspensions | Thread suspensions shorter than the heartbeat silence threshold (~2s) may not trigger an alert. The threshold is a tradeoff against false positives from scheduler jitter. |

---

## C++23 Features Used

| Feature | Used in |
|---|---|
| `std::expected<T,E>` with `.and_then()`, `.transform()`, `.or_else()` | All subsystems — explicit, composable error handling |
| `std::format` | `Logger`, `MemoryIntegrityMonitor`, `EtwSessionMonitor` |
| `std::println` | `Logger` |
| `std::flat_map` | `EventDispatcher` handler table |
| `std::jthread` + `std::stop_token` | `GuardianOrchestrator`, `HeartbeatMonitor` |
| `std::source_location` | `Logger` |
| `std::span` | `MemoryIntegrityMonitor::sha256` |
| `std::optional` | `GuardianOrchestrator` launch path, ETW property lookup |
| Designated initialisers | `Events.hpp` factory functions |# processguard
