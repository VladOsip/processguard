#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <vector>

#include "Result.hpp"
#include "Events.hpp"

#pragma comment(lib, "bcrypt.lib")

namespace pg {

// ---------------------------------------------------------------------------
// MemoryIntegrityMonitor  (C++23 edition)
//
// Changes from C++20 version:
//
//   WOW64 support:
//     Reads the Machine field from the COFF header and branches to
//     IMAGE_NT_HEADERS32 or IMAGE_NT_HEADERS64 as appropriate.
//     Uses EnumProcessModulesEx(LIST_MODULES_32BIT) for 32-bit targets
//     so the module list is always complete.
//
//   SHA-256 instead of FNV-1a:
//     BCrypt SHA-256 (Windows CNG) replaces the hand-rolled FNV-1a hash.
//     SHA-256 is collision-resistant against adversaries: an attacker cannot
//     craft a patch that produces the same hash as the original bytes.
//     FNV-1a is fast and fine for non-adversarial change detection, but
//     a security tool that explicitly defends against adversaries should
//     use a cryptographic hash.
//     The 32-byte digest is stored as a std::array<uint8_t,32>.
//
//   Bounds checking:
//     Every pointer derived from PE header fields is validated against
//     the known module size (SizeOfImage) before use.
// ---------------------------------------------------------------------------

struct MonitorError {
    std::string message;
    DWORD       winCode{ 0 };
};

using Sha256Digest = std::array<uint8_t, 32>;

struct SectionSnapshot {
    std::string  name;
    Sha256Digest hash{};
    std::uintptr_t rva{ 0 };
    std::size_t  size{ 0 };
};

class MemoryIntegrityMonitor {
public:
    using AlertCallback = std::function<void(SecurityEvent)>;

    explicit MemoryIntegrityMonitor(HANDLE hProcess, AlertCallback cb);

    Result<void, MonitorError> initialize();
    void poll();

    [[nodiscard]] const std::vector<SectionSnapshot>& sections() const {
        return m_sections;
    }

private:
    // Bitness-agnostic section parsing.
    // Templated on the NT headers type (32 or 64 bit).
    template<typename NtHeaders>
    Result<std::vector<SectionSnapshot>, MonitorError>
    parseSectionsFromHeaders(std::uintptr_t ntAddr, std::size_t imageSize);

    Result<std::vector<SectionSnapshot>, MonitorError> parsePeSections();

    Result<std::vector<std::byte>, MonitorError>
    readRemoteMemory(std::uintptr_t address, std::size_t size) const;

    static Result<Sha256Digest, MonitorError>
    sha256(std::span<const std::byte> data);

    HANDLE        m_hProcess;
    AlertCallback m_onAlert;
    bool          m_is32BitTarget{ false };

    std::uintptr_t            m_imageBase{ 0 };
    std::size_t               m_imageSize{ 0 };
    std::vector<SectionSnapshot> m_sections;
};

} // namespace pg
