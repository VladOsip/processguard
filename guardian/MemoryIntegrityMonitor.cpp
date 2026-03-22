#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>

#include "MemoryIntegrityMonitor.hpp"
#include "Logger.hpp"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "bcrypt.lib")

namespace pg {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

MemoryIntegrityMonitor::MemoryIntegrityMonitor(HANDLE hProcess, AlertCallback cb)
    : m_hProcess(hProcess), m_onAlert(std::move(cb))
{}

// ---------------------------------------------------------------------------
// initialize()
// ---------------------------------------------------------------------------

Result<void, MonitorError> MemoryIntegrityMonitor::initialize() {
    // EnumProcessModulesEx with LIST_MODULES_ALL works for both 32-bit and
    // 64-bit targets. We pass it here to discover the main module.
    HMODULE hMods[1]{};
    DWORD   needed{};

    // First call with LIST_MODULES_ALL to get the right bitness context.
    if (!EnumProcessModulesEx(m_hProcess, hMods, sizeof(hMods),
                               &needed, LIST_MODULES_ALL))
        return std::unexpected(MonitorError{
            "EnumProcessModulesEx failed", GetLastError()
        });

    MODULEINFO mi{};
    if (!GetModuleInformation(m_hProcess, hMods[0], &mi, sizeof(mi)))
        return std::unexpected(MonitorError{
            "GetModuleInformation failed", GetLastError()
        });

    m_imageBase = reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll);
    m_imageSize = mi.SizeOfImage;
    Logger::info("Target image base: 0x{:016X}, size: {} bytes",
                 m_imageBase, m_imageSize);

    auto sectResult = parsePeSections();
    if (!sectResult)
        return std::unexpected(sectResult.error());

    m_sections = std::move(*sectResult);
    Logger::info("Tracking {} executable section(s)", m_sections.size());
    return {};
}

// ---------------------------------------------------------------------------
// parsePeSections()
//
// Reads the DOS header, validates the magic, follows e_lfanew to the NT
// headers, reads the Machine field to determine bitness, then delegates
// to the templated parseSectionsFromHeaders<>.
//
// All pointer arithmetic is bounds-checked against m_imageSize before
// any ReadProcessMemory call.
// ---------------------------------------------------------------------------

Result<std::vector<SectionSnapshot>, MonitorError>
MemoryIntegrityMonitor::parsePeSections() {
    // --- DOS header ---
    if (sizeof(IMAGE_DOS_HEADER) > m_imageSize)
        return std::unexpected(MonitorError{ "Image too small for DOS header" });

    auto dosResult = readRemoteMemory(m_imageBase, sizeof(IMAGE_DOS_HEADER));
    if (!dosResult)
        return std::unexpected(dosResult.error());

    const auto* dosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(dosResult->data());
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return std::unexpected(MonitorError{ "Invalid DOS signature (expected MZ)" });

    // Bounds check e_lfanew before following it.
    const DWORD ntOffset = dosHdr->e_lfanew;
    if (ntOffset < sizeof(IMAGE_DOS_HEADER) ||
        ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > m_imageSize)
        return std::unexpected(MonitorError{ "e_lfanew out of bounds" });

    std::uintptr_t ntAddr = m_imageBase + ntOffset;

    // --- Read just enough to identify bitness: Signature + FileHeader ---
    constexpr size_t MIN_NT_READ = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    auto sigResult = readRemoteMemory(ntAddr, MIN_NT_READ);
    if (!sigResult)
        return std::unexpected(sigResult.error());

    const DWORD sig = *reinterpret_cast<const DWORD*>(sigResult->data());
    if (sig != IMAGE_NT_SIGNATURE)
        return std::unexpected(MonitorError{ "Invalid NT signature (expected PE)" });

    const auto* fileHdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        sigResult->data() + sizeof(DWORD));
    const WORD machine = fileHdr->Machine;

    // --- Dispatch on bitness ---
    if (machine == IMAGE_FILE_MACHINE_I386) {
        Logger::info("Target is 32-bit (WOW64)");
        m_is32BitTarget = true;
        return parseSectionsFromHeaders<IMAGE_NT_HEADERS32>(ntAddr, m_imageSize);
    }
    else if (machine == IMAGE_FILE_MACHINE_AMD64 ||
             machine == IMAGE_FILE_MACHINE_ARM64) {
        Logger::info("Target is 64-bit");
        m_is32BitTarget = false;
        return parseSectionsFromHeaders<IMAGE_NT_HEADERS64>(ntAddr, m_imageSize);
    }
    else {
        return std::unexpected(MonitorError{
            std::format("Unsupported machine type: 0x{:04X}", machine)
        });
    }
}

// ---------------------------------------------------------------------------
// parseSectionsFromHeaders<NtHeaders>
//
// Templated so the same logic handles both 32-bit and 64-bit PE layouts.
// The only structural difference between IMAGE_NT_HEADERS32 and
// IMAGE_NT_HEADERS64 is the OptionalHeader -- the section table that
// immediately follows has the same IMAGE_SECTION_HEADER layout in both cases.
// ---------------------------------------------------------------------------

template<typename NtHeaders>
Result<std::vector<SectionSnapshot>, MonitorError>
MemoryIntegrityMonitor::parseSectionsFromHeaders(std::uintptr_t ntAddr,
                                                  std::size_t    imageSize) {
    // Bounds check the full NT headers struct.
    const std::uintptr_t ntOffset = ntAddr - m_imageBase;
    if (ntOffset + sizeof(NtHeaders) > imageSize)
        return std::unexpected(MonitorError{ "NT headers exceed image bounds" });

    auto ntResult = readRemoteMemory(ntAddr, sizeof(NtHeaders));
    if (!ntResult)
        return std::unexpected(ntResult.error());

    const auto* ntHdr = reinterpret_cast<const NtHeaders*>(ntResult->data());

    const WORD  numSections = ntHdr->FileHeader.NumberOfSections;
    const WORD  optHdrSize  = ntHdr->FileHeader.SizeOfOptionalHeader;

    // Sanity-check section count to avoid huge allocations from corrupt headers.
    if (numSections > 96)
        return std::unexpected(MonitorError{
            std::format("Implausible section count: {}", numSections)
        });

    // Section table starts immediately after the optional header.
    const std::uintptr_t sectionTableAddr = ntAddr
        + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)  // same offset in both
        + optHdrSize;

    const std::uintptr_t sectionTableOffset = sectionTableAddr - m_imageBase;
    const std::size_t    sectionTableSize   = numSections * sizeof(IMAGE_SECTION_HEADER);

    if (sectionTableOffset + sectionTableSize > imageSize)
        return std::unexpected(MonitorError{ "Section table exceeds image bounds" });

    auto sectResult = readRemoteMemory(sectionTableAddr, sectionTableSize);
    if (!sectResult)
        return std::unexpected(sectResult.error());

    const auto* headers = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        sectResult->data());

    std::vector<SectionSnapshot> snapshots;

    for (WORD i = 0; i < numSections; ++i) {
        const auto& sec = headers[i];

        if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

        // Bounds check section VA and size.
        const std::size_t sectionSize = sec.Misc.VirtualSize;
        if (sec.VirtualAddress == 0 ||
            static_cast<std::size_t>(sec.VirtualAddress) + sectionSize > imageSize) {
            Logger::warn("Section {} has out-of-bounds VA -- skipping", i);
            continue;
        }

        const std::uintptr_t sectionVa = m_imageBase + sec.VirtualAddress;

        auto dataResult = readRemoteMemory(sectionVa, sectionSize);
        if (!dataResult) {
            Logger::warn("Could not read section {} -- skipping", i);
            continue;
        }

        auto hashResult = sha256(*dataResult);
        if (!hashResult) {
            Logger::warn("SHA-256 failed for section {} -- skipping", i);
            continue;
        }

        char nameBuf[9]{};
        std::memcpy(nameBuf, sec.Name, 8);

        snapshots.push_back(SectionSnapshot{
            .name = nameBuf,
            .hash = *hashResult,
            .rva  = sec.VirtualAddress,
            .size = sectionSize,
        });

        Logger::debug("Section '{}' @ RVA 0x{:08X}, size {}, SHA-256: {:02x}{:02x}...{:02x}{:02x}",
                      nameBuf, sec.VirtualAddress, sectionSize,
                      (*hashResult)[0], (*hashResult)[1],
                      (*hashResult)[30], (*hashResult)[31]);
    }

    return snapshots;
}

// ---------------------------------------------------------------------------
// poll()
// ---------------------------------------------------------------------------

void MemoryIntegrityMonitor::poll() {
    for (auto& snap : m_sections) {
        const std::uintptr_t va = m_imageBase + snap.rva;

        auto dataResult = readRemoteMemory(va, snap.size);
        if (!dataResult) {
            m_onAlert(makeErrorEvent("Failed to re-read section " + snap.name));
            continue;
        }

        auto hashResult = sha256(*dataResult);
        if (!hashResult) {
            m_onAlert(makeErrorEvent("SHA-256 failed for section " + snap.name));
            continue;
        }

        if (*hashResult != snap.hash) {
            const std::string detail = std::format(
                "Section: {} | SHA-256 changed (first bytes now: {:02x}{:02x}{:02x}{:02x})",
                snap.name,
                (*hashResult)[0], (*hashResult)[1],
                (*hashResult)[2], (*hashResult)[3]);

            Logger::error("Integrity violation in section '{}'!", snap.name);
            m_onAlert(makeMemoryEvent("Executable section modified", detail));

            snap.hash = *hashResult;  // update baseline to avoid alert spam
        }
    }
}

// ---------------------------------------------------------------------------
// readRemoteMemory()
// ---------------------------------------------------------------------------

Result<std::vector<std::byte>, MonitorError>
MemoryIntegrityMonitor::readRemoteMemory(std::uintptr_t address,
                                          std::size_t size) const {
    std::vector<std::byte> buf(size);
    SIZE_T bytesRead{};

    if (!ReadProcessMemory(m_hProcess,
                           reinterpret_cast<LPCVOID>(address),
                           buf.data(), size, &bytesRead)
        || bytesRead != size)
    {
        return std::unexpected(MonitorError{
            std::format("ReadProcessMemory failed at 0x{:016X}", address),
            GetLastError()
        });
    }

    return buf;
}

// ---------------------------------------------------------------------------
// sha256()
//
// Computes a SHA-256 digest using the Windows BCrypt (CNG) API.
// BCrypt is available on all supported Windows versions (Vista+) and is
// FIPS-compliant. Unlike FNV-1a, SHA-256 is collision-resistant -- an
// adversary cannot craft a patch that produces the same digest.
//
// BCryptOpenAlgorithmProvider / BCryptCreateHash / BCryptHashData /
// BCryptFinishHash are all documented stable APIs.
// ---------------------------------------------------------------------------

Result<Sha256Digest, MonitorError>
MemoryIntegrityMonitor::sha256(std::span<const std::byte> data) {
    BCRYPT_ALG_HANDLE hAlg{};
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);

    if (!BCRYPT_SUCCESS(status))
        return std::unexpected(MonitorError{
            std::format("BCryptOpenAlgorithmProvider failed: 0x{:08X}",
                        static_cast<unsigned>(status))
        });

    BCRYPT_HASH_HANDLE hHash{};
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::unexpected(MonitorError{
            std::format("BCryptCreateHash failed: 0x{:08X}",
                        static_cast<unsigned>(status))
        });
    }

    status = BCryptHashData(hHash,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(data.data())),
        static_cast<ULONG>(data.size()), 0);

    Sha256Digest digest{};
    if (BCRYPT_SUCCESS(status))
        status = BCryptFinishHash(hHash, digest.data(),
                                   static_cast<ULONG>(digest.size()), 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status))
        return std::unexpected(MonitorError{
            std::format("BCrypt hash computation failed: 0x{:08X}",
                        static_cast<unsigned>(status))
        });

    return digest;
}

} // namespace pg
