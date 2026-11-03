// FreezeFixF4 2.0.2 — constrained Archive2 index recovery for Fallout 4 1.10.163.
// Recovery executes on the original writer, before BaseInsert mutates anything.
// A watchdog only reports observations; it never edits or suspends game state.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include <fcntl.h>
#include <io.h>
#include <array>
#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <utility>
#include <vector>

using UInt32 = unsigned int;
using UInt64 = unsigned long long;
using UInt8 = unsigned char;
#include "f4se/PluginAPI.h"
#include "f4se/f4se_version.h"
#include "minhook/include/MinHook.h"
#include "address_library.h"
#include "archive_index.h"
#include "native_patch.h"
#include "install_lifecycle.h"
#include "monitor_core.h"
#include "runtime_profile.h"
#include "detour_contract.h"

namespace {
namespace archive = freezefix::archive;
constexpr UInt32 kRuntime = RUNTIME_VERSION_1_10_163;
constexpr const char* kVersion = "2.0.3";

struct Config {
    bool enabled = true;
    bool fix = true;
    bool monitor = false;
    DWORD stall_ms = 3000;
    DWORD poll_ms = 250;
} g_config;

FILE* g_log = nullptr;
SRWLOCK g_log_lock = SRWLOCK_INIT;
wchar_t g_directory[MAX_PATH]{};
PluginHandle g_plugin = static_cast<PluginHandle>(kPluginHandle_Invalid);
std::atomic<bool> g_install_attempted{false};
std::atomic<bool> g_active{false};
std::atomic<std::uint64_t> g_rebuilds{0}, g_declines{0}, g_dropped_events{0}, g_dropped_waits{0};
std::atomic<std::uint64_t> g_extended_declines{0}, g_suppressed_extended_events{0};
std::atomic<std::uint32_t> g_highest_extended_incoming{0};
freezefix::MonitorCore<512> g_waits;
std::uintptr_t g_image_base = 0;
HANDLE g_stop_event = nullptr;
HANDLE g_watchdog = nullptr;

using LockRead = void (*)(void*);
using BaseInsert = bool (*)(void*, std::uint32_t, const archive::Key**);
LockRead g_original_lock_read = nullptr;
BaseInsert g_original_insert = nullptr;

struct DetourBytes {
    std::uintptr_t address = 0;
    freezefix::detour::ReadKind kind = freezefix::detour::ReadKind::Code;
    std::vector<std::uint8_t> bytes;
};
struct DetourModule {
    std::uintptr_t base = 0, endpoint = 0;
    std::array<wchar_t, MAX_PATH> path{};
};
struct CodeContract {
    const freezefix::CodeIdentity* identity = nullptr;
    std::uintptr_t address = 0;
    std::vector<std::uint8_t> expected;
    std::vector<DetourBytes> detour_bytes;
    std::vector<DetourModule> modules;
};
std::vector<CodeContract> g_code_contracts;
bool g_contracts_ready = false;
bool g_extended_archive_storage = false;

// MinHook replaces exactly five entry bytes with an E9 to its x64 jump relay.
// The insert trampoline relocates a five-byte MOV; lock_read relocates its
// two-byte PUSH plus four-byte SUB, leaving entry byte six unchanged. Neither
// verified routine needs hotpatch-above. Validate the patch separately from
// every original byte that MinHook leaves in place.
struct InstalledHook {
    std::uintptr_t entry = 0;
    std::uintptr_t relay = 0;
    std::array<std::uint8_t, 5> prefix{};
    std::array<std::uint8_t, 14> relay_bytes{};
    bool valid = false;
};
InstalledHook g_insert_hook, g_read_hook;

void Log(const char* format, ...) {
    if (!g_log) return;
    AcquireSRWLockExclusive(&g_log_lock);
    SYSTEMTIME time{};
    GetLocalTime(&time);
    std::fprintf(g_log, "[%02u:%02u:%02u.%03u] ", time.wHour, time.wMinute,
                 time.wSecond, time.wMilliseconds);
    va_list arguments;
    va_start(arguments, format);
    std::vfprintf(g_log, format, arguments);
    va_end(arguments);
    std::fputc('\n', g_log);
    std::fflush(g_log);
    ReleaseSRWLockExclusive(&g_log_lock);
}

bool InitializePaths() {
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(&InitializePaths), &module)) return false;
    wchar_t path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
    if (!length || length >= MAX_PATH) return false;
    wchar_t* separator = wcsrchr(path, L'\\');
    if (!separator) return false;
    *separator = 0;
    return wcsncpy_s(g_directory, path, _TRUNCATE) == 0;
}

void OpenLog() {
    wchar_t path[MAX_PATH]{};
    if (_snwprintf_s(path, _TRUNCATE, L"%s\\FreezeFixF4.log", g_directory) < 0) return;
    WIN32_FILE_ATTRIBUTE_DATA attributes{};
    if (GetFileAttributesExW(path, GetFileExInfoStandard, &attributes) &&
        (attributes.nFileSizeHigh || attributes.nFileSizeLow > 2u * 1024u * 1024u)) {
        wchar_t previous[MAX_PATH]{};
        if (_snwprintf_s(previous, _TRUNCATE, L"%s\\FreezeFixF4.log.1", g_directory) >= 0)
            MoveFileExW(path, previous, MOVEFILE_REPLACE_EXISTING);
    }
    HANDLE handle = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return;
    const int descriptor = _open_osfhandle(reinterpret_cast<intptr_t>(handle), _O_APPEND | _O_TEXT);
    if (descriptor == -1) { CloseHandle(handle); return; }
    g_log = _fdopen(descriptor, "a");
    if (!g_log) _close(descriptor);
}

void ReadConfig() {
    wchar_t path[MAX_PATH]{};
    if (_snwprintf_s(path, _TRUNCATE, L"%s\\FreezeFixF4.ini", g_directory) < 0) {
        g_config.enabled = false;
        return;
    }
    g_config.enabled = GetPrivateProfileIntW(L"FreezeFixF4", L"Enabled", 1, path) != 0;
    g_config.fix = GetPrivateProfileIntW(L"FreezeFixF4", L"Fix", 1, path) != 0;
    g_config.monitor = GetPrivateProfileIntW(L"FreezeFixF4", L"MonitorLockWaits", 0, path) != 0;
    g_config.stall_ms = GetPrivateProfileIntW(L"FreezeFixF4", L"StallMilliseconds", 3000, path);
    g_config.poll_ms = GetPrivateProfileIntW(L"FreezeFixF4", L"PollMilliseconds", 250, path);
    if (g_config.stall_ms < 1000) g_config.stall_ms = 1000;
    if (g_config.stall_ms > 60000) g_config.stall_ms = 60000;
    if (g_config.poll_ms < 50) g_config.poll_ms = 50;
    if (g_config.poll_ms > 5000) g_config.poll_ms = 5000;
    for (const wchar_t* obsolete : {L"BreakMilliseconds", L"WriterCpuPercent", L"SpinSamples"}) {
        wchar_t value[32]{};
        if (GetPrivateProfileStringW(L"FreezeFixF4", obsolete, L"", value, 32, path))
            Log("configuration: %ls is obsolete and ignored; no watchdog recovery exists", obsolete);
    }
}

// Events are preallocated. Hook code neither allocates event records nor logs
// while holding an engine lock. Windows SLIST operations publish complete nodes.
enum class CapacitySource { Unavailable, ValidatedSnapshot, RawHeader };
struct HeaderObservation {
    bool readable = false;
    std::array<std::uint32_t, 8> words{};
};
struct Event {
    const char* kind = nullptr;
    const char* reason = nullptr;
    DWORD thread_id = 0;
    std::uintptr_t table = 0;
    std::uint32_t index = 0;
    std::uint32_t capacity = 0;
    CapacitySource capacity_source = CapacitySource::Unavailable;
    bool header_requested = false;
    HeaderObservation header{};
    std::uint64_t reason_occurrence = 0;
};
struct alignas(MEMORY_ALLOCATION_ALIGNMENT) EventNode { SLIST_ENTRY link{}; Event event{}; };
alignas(MEMORY_ALLOCATION_ALIGNMENT) SLIST_HEADER g_free_events{};
alignas(MEMORY_ALLOCATION_ALIGNMENT) SLIST_HEADER g_pending_events{};
EventNode g_events[32];

void QueueEvent(const Event& event) noexcept {
    auto* node = reinterpret_cast<EventNode*>(InterlockedPopEntrySList(&g_free_events));
    if (!node) { g_dropped_events.fetch_add(1, std::memory_order_relaxed); return; }
    node->event = event;
    InterlockedPushEntrySList(&g_pending_events, &node->link);
}

void QueueEvent(const char* kind, const char* reason, std::uintptr_t table,
                std::uint32_t index, std::uint32_t capacity,
                CapacitySource source = CapacitySource::ValidatedSnapshot) noexcept {
    Event event;
    event.kind = kind;
    event.reason = reason;
    event.thread_id = GetCurrentThreadId();
    event.table = table;
    event.index = index;
    event.capacity = capacity;
    event.capacity_source = source;
    QueueEvent(event);
}

bool ReadMemory(std::uintptr_t address, void* output, std::size_t length) noexcept {
    if (!address || !output || !length || length - 1 > UINTPTR_MAX - address) return false;
    SIZE_T read = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
                             output, length, &read) && read == length;
}

HeaderObservation ObserveRawHeader(std::uintptr_t self) noexcept {
    HeaderObservation result;
    std::array<std::uint32_t, 8> words{};
    // This is exactly one bounded read of the raw first 0x20 bytes. It never
    // follows a field as a pointer, and neither readability nor word[4] proves
    // that this object has the supported table layout. Discard partial reads.
    if (ReadMemory(self, words.data(), sizeof(words))) {
        result.words = words;
        result.readable = true;
    }
    return result;
}

// Extended indices require the vector layout below. A capture that cannot read
// it is the expected high-volume case on an archive-extended modlist, so it is
// counted in full and reported on powers of two.
void RecordExtendedStorageDecline(std::uintptr_t self, std::uint32_t incoming) noexcept {
    g_declines.fetch_add(1, std::memory_order_relaxed);
    const auto occurrence = g_extended_declines.fetch_add(1, std::memory_order_relaxed) + 1;
    auto highest = g_highest_extended_incoming.load(std::memory_order_relaxed);
    while (highest < incoming &&
           !g_highest_extended_incoming.compare_exchange_strong(highest, incoming,
                std::memory_order_relaxed, std::memory_order_relaxed)) {}

    // Sample this one expected high-volume reason at cumulative occurrence
    // numbers 1,2,4,8,... across all objects. Count every decline, and preserve
    // the highest observed incoming index even when its report is suppressed.
    // Non-sampled calls do not read any engine memory or consume an event node.
    if (!occurrence || (occurrence & (occurrence - 1)) != 0) {
        g_suppressed_extended_events.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    Event event;
    event.kind = "DECLINED";
    event.reason = "extended-archive-keys-unreadable-or-layout-mismatch";
    event.thread_id = GetCurrentThreadId();
    event.table = self;
    event.index = incoming;
    event.header_requested = true;
    event.header = ObserveRawHeader(self);
    if (event.header.readable) {
        event.capacity = event.header.words[4]; // Raw +0x10 field; deliberately unvalidated.
        event.capacity_source = CapacitySource::RawHeader;
    }
    event.reason_occurrence = occurrence;
    QueueEvent(event);
}

bool AddAddress(std::uintptr_t address, std::size_t offset, std::uintptr_t& result) noexcept {
    if (offset > UINTPTR_MAX - address) return false;
    result = address + offset;
    return true;
}

bool Disjoint(std::uintptr_t a, std::size_t a_size,
              std::uintptr_t b, std::size_t b_size) noexcept {
    return a <= b ? b - a >= a_size : a - b >= b_size;
}

bool AccessibleRange(std::uintptr_t address, std::size_t length, bool executable,
                     bool image_only = true) noexcept {
    if (!address || !length || length - 1 > UINTPTR_MAX - address) return false;
    while (length) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<const void*>(address), &info, sizeof(info)) != sizeof(info) ||
            info.State != MEM_COMMIT || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
        const DWORD protection = info.Protect & 0xFFu;
        const bool allowed = executable
            ? ((!image_only || info.Type == MEM_IMAGE) && (protection == PAGE_EXECUTE_READ ||
               protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY))
            : (protection == PAGE_READWRITE || protection == PAGE_WRITECOPY);
        if (!allowed) return false;
        const auto begin = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
        if (address < begin || address - begin >= info.RegionSize) return false;
        const std::size_t available = info.RegionSize - static_cast<std::size_t>(address - begin);
        const std::size_t step = length < available ? length : available;
        length -= step;
        if (length && !AddAddress(address, step, address)) return false;
    }
    return true;
}

struct Image {
    std::uintptr_t base = 0;
    std::uint32_t size = 0;
    std::vector<IMAGE_SECTION_HEADER> sections;
};

bool ReadImage(Image& image, std::uintptr_t base = 0) {
    image.base = base ? base : reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    IMAGE_DOS_HEADER dos{};
    if (!ReadMemory(image.base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000) return false;
    IMAGE_NT_HEADERS64 nt{};
    std::uintptr_t nt_address = 0;
    if (!AddAddress(image.base, static_cast<std::size_t>(dos.e_lfanew), nt_address) ||
        !ReadMemory(nt_address, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64) ||
        nt.FileHeader.NumberOfSections == 0 || nt.FileHeader.NumberOfSections > 96) return false;
    image.size = nt.OptionalHeader.SizeOfImage;
    const std::uint64_t sections_rva = static_cast<std::uint32_t>(dos.e_lfanew) + sizeof(nt);
    const std::size_t bytes = nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (!freezefix::contains_range(image.size, sections_rva, bytes)) return false;
    image.sections.resize(nt.FileHeader.NumberOfSections);
    return ReadMemory(image.base + sections_rva, image.sections.data(), bytes);
}

bool ReadCode(const Image& image, std::uint64_t rva, std::size_t length,
              std::vector<std::uint8_t>& bytes) {
    if (!freezefix::contains_range(image.size, rva, length)) return false;
    bool in_code = false;
    for (const auto& section : image.sections) {
        if ((section.Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)) ==
            (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ) && rva >= section.VirtualAddress &&
            freezefix::contains_range(section.Misc.VirtualSize, rva - section.VirtualAddress, length)) {
            in_code = true;
            break;
        }
    }
    std::uintptr_t address = 0;
    if (!in_code || !AddAddress(image.base, static_cast<std::size_t>(rva), address) ||
        !AccessibleRange(address, length, true)) return false;
    bytes.resize(length);
    return ReadMemory(address, bytes.data(), length);
}

bool Sha256(const std::vector<std::uint8_t>& bytes, std::array<std::uint8_t, 32>& output) {
    if (bytes.size() > ULONG_MAX) return false;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    bool success = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0;
    if (success)
        success = BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()),
                                 static_cast<ULONG>(bytes.size()), 0) >= 0;
    if (success) success = BCryptFinishHash(hash, output.data(), static_cast<ULONG>(output.size()), 0) >= 0;
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return success;
}

struct DetourDiagnostic {
    std::size_t offset = 0;
    std::uintptr_t target = 0, endpoint = 0;
    DetourModule module{};
    const char* reason = "unresolved";
};
struct IdentityDiagnostic {
    std::array<std::uint8_t, 32> actual{}, normalized{};
    bool actual_hashed = false, normalized_hashed = false, accepted = false, detoured = false;
    bool prefix_comparable = false;
    std::size_t first_difference = freezefix::detour::kNoDifference;
    std::size_t remaining_difference = freezefix::detour::kNoDifference;
    const char* reason = "unreadable-routine";
    std::vector<DetourDiagnostic> detours;
};

bool CaptureDetourModule(std::uintptr_t endpoint, DetourModule& output) {
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(endpoint), &module)) return false;
    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQuery(reinterpret_cast<const void*>(endpoint), &memory, sizeof(memory)) != sizeof(memory) ||
        memory.Type != MEM_IMAGE || memory.AllocationBase != module) return false;
    Image image;
    std::vector<std::uint8_t> prefix;
    const auto base = reinterpret_cast<std::uintptr_t>(module);
    if (endpoint < base || !ReadImage(image, base) || !ReadCode(image, endpoint - base, 16, prefix)) return false;
    DetourModule candidate;
    candidate.base = base;
    candidate.endpoint = endpoint;
    const DWORD length = GetModuleFileNameW(module, candidate.path.data(),
                                            static_cast<DWORD>(candidate.path.size()));
    if (!length || length >= candidate.path.size()) return false;
    output = candidate;
    return true;
}

// Module lookups and pinning happen only during installation. The commit path
// uses VirtualQuery and retained bytes, avoiding the loader lock under an engine lock.
bool DetourModuleStillMapped(const DetourModule& module) noexcept {
    MEMORY_BASIC_INFORMATION memory{};
    return module.base && module.endpoint &&
           VirtualQuery(reinterpret_cast<const void*>(module.endpoint), &memory, sizeof(memory)) == sizeof(memory) &&
           memory.Type == MEM_IMAGE &&
           reinterpret_cast<std::uintptr_t>(memory.AllocationBase) == module.base &&
           AccessibleRange(module.endpoint, 16, true);
}

bool ValidateIdentity(const freezefix::CodeIdentity& identity, std::uintptr_t address,
                      const std::vector<std::uint8_t>& observed, CodeContract& output,
                      IdentityDiagnostic& diagnostic) {
    namespace detour = freezefix::detour;
    output = {};
    diagnostic = {};
    diagnostic.actual_hashed = Sha256(observed, diagnostic.actual);
    diagnostic.prefix_comparable = identity.prefix_crc && identity.prefix_count == observed.size() &&
                                   observed.size() == identity.length;
    diagnostic.first_difference = detour::FirstDifference(observed.data(), observed.size(),
                                                         identity.prefix_crc, identity.prefix_count);
    if (!address || observed.size() != identity.length || !diagnostic.actual_hashed) {
        diagnostic.reason = "invalid-range-or-hash-failure";
        return false;
    }
    CodeContract candidate;
    candidate.identity = &identity;
    candidate.address = address;
    candidate.expected = observed;  // Preserve the ACTUAL accepted code, including external detours.
    if (diagnostic.actual == identity.sha256) {
        output = std::move(candidate);
        diagnostic.accepted = true;
        diagnostic.reason = "native-sha256";
        return true;
    }
    if (!identity.windows || !identity.window_count || identity.window_count > 4) {
        diagnostic.reason = "no-approved-detour-windows";
        return false;
    }
    auto normalized = observed;
    bool saw_detour = false, valid = true;
    diagnostic.reason = "remaining-bytes-mismatch";
    std::size_t previous_end = 0;
    for (std::size_t i = 0; i < identity.window_count; ++i) {
        const auto& window = identity.windows[i];
        if (window.offset < previous_end || window.offset > observed.size() ||
            window.length > observed.size() - window.offset) {
            diagnostic.reason = "invalid-window-profile";
            return false;
        }
        previous_end = window.offset + window.length;
        const auto parsed = detour::ParseWindow(observed.data(), observed.size(), address, window);
        if (parsed.state == detour::WindowState::Native) continue;
        if (parsed.state != detour::WindowState::Detoured) {
            diagnostic.reason = detour::ReasonName(parsed.reason);
            valid = false;
            continue;
        }
        saw_detour = true;
        DetourDiagnostic detail;
        detail.offset = window.offset;
        detail.target = parsed.target;
        auto read = [&](std::uintptr_t at, void* destination, std::size_t length, detour::ReadKind kind) {
            if (!length || length > detour::kMaxRead || candidate.detour_bytes.size() >= 256 ||
                (kind == detour::ReadKind::Code && !AccessibleRange(at, length, true, false)) ||
                !ReadMemory(at, destination, length)) return false;
            const auto* bytes = static_cast<const std::uint8_t*>(destination);
            candidate.detour_bytes.push_back({at, kind, std::vector<std::uint8_t>(bytes, bytes + length)});
            return true;
        };
        auto module = [&](std::uintptr_t endpoint) {
            DetourModule identified;
            if (!CaptureDetourModule(endpoint, identified)) return false;
            std::array<std::uint8_t, 16> prefix{};
            if (!read(endpoint, prefix.data(), prefix.size(), detour::ReadKind::Code)) return false;
            detail.module = identified;
            return true;
        };
        const auto resolution = detour::Resolve(parsed.target, parsed.continuation, window.stub, read, module);
        detail.endpoint = resolution.endpoint;
        detail.reason = detour::ReasonName(resolution.reason);
        diagnostic.detours.push_back(detail);
        if (!resolution.accepted) {
            valid = false;
            diagnostic.reason = detail.reason;
            continue;
        }
        candidate.modules.push_back(detail.module);
        if (!detour::NormalizePatch(normalized.data(), normalized.size(), window)) {
            valid = false;
            diagnostic.reason = "normalization-failed";
        }
    }
    diagnostic.normalized_hashed = Sha256(normalized, diagnostic.normalized);
    diagnostic.remaining_difference = detour::FirstDifference(normalized.data(), normalized.size(),
                                                             identity.prefix_crc, identity.prefix_count);
    if (!valid || !saw_detour || !diagnostic.normalized_hashed || diagnostic.normalized != identity.sha256)
        return false;

    // The jump destination must remain a loaded image for the lifetime of the
    // hook. Pin only after both the detour and every remaining native byte pass.
    for (const auto& module : candidate.modules) {
        HMODULE pinned = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                               reinterpret_cast<LPCWSTR>(module.endpoint), &pinned) ||
            reinterpret_cast<std::uintptr_t>(pinned) != module.base || !DetourModuleStillMapped(module)) {
            diagnostic.reason = "detour-module-lifetime-check-failed";
            return false;
        }
    }
    output = std::move(candidate);
    diagnostic.detoured = true;
    diagnostic.accepted = true;
    diagnostic.reason = "verified-detours-and-native-remainder";
    return true;
}

std::string DigestText(const std::array<std::uint8_t, 32>& digest) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result(64, '0');
    for (std::size_t i = 0; i < digest.size(); ++i) {
        result[2 * i] = digits[digest[i] >> 4];
        result[2 * i + 1] = digits[digest[i] & 15];
    }
    return result;
}

std::string HexText(std::uint64_t value) {
    char buffer[24]{};
    std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(value));
    return buffer;
}

std::string ModuleName(const DetourModule& module) {
    if (!module.base) return "unresolved";
    const wchar_t* name = wcsrchr(module.path.data(), L'\\');
    name = name ? name + 1 : module.path.data();
    const int size = WideCharToMultiByte(CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) return "unknown";
    std::string result(static_cast<std::size_t>(size), '\0');
    if (!WideCharToMultiByte(CP_UTF8, 0, name, -1, result.data(), size, nullptr, nullptr)) return "unknown";
    result.resize(static_cast<std::size_t>(size - 1));
    return result;
}

std::string FormatIdentityDiagnostic(const freezefix::CodeIdentity& identity,
                                     const IdentityDiagnostic& diagnostic) {
    const bool known_prefixes = diagnostic.actual_hashed && diagnostic.prefix_comparable;
    auto offset = [&](std::size_t value) {
        return value != freezefix::detour::kNoDifference ? "+" + HexText(value) :
               std::string(known_prefixes ? "none" : "unavailable");
    };
    std::string line = diagnostic.accepted ? "CODE_IDENTITY " : "INERT code identity mismatch: ";
    line += identity.name;
    line += " rva=" + HexText(identity.rva);
    line += " result=" + std::string(diagnostic.accepted ? (diagnostic.detoured ? "accepted-detour" : "native") : "rejected");
    line += " expected_sha256=" + DigestText(identity.sha256);
    line += " actual_sha256=" + (diagnostic.actual_hashed ? DigestText(diagnostic.actual) : "unavailable");
    line += " first_diff=" + offset(diagnostic.first_difference);
    if (diagnostic.normalized_hashed) {
        line += " normalized_sha256=" + DigestText(diagnostic.normalized);
        line += " remaining_diff=" + offset(diagnostic.remaining_difference);
    }
    if (diagnostic.detours.empty()) line += " target_module=unresolved";
    for (const auto& detail : diagnostic.detours) {
        line += " detour=+" + HexText(detail.offset) + "->" + HexText(detail.target);
        line += " target_module=" + ModuleName(detail.module);
        if (detail.module.base) line += "+" + HexText(detail.endpoint - detail.module.base);
        line += " endpoint=" + HexText(detail.endpoint) + " resolution=" + detail.reason;
    }
    line += " reason=" + std::string(diagnostic.reason);
    return line;
}

bool ValidateCode(const Image& image) {
    g_contracts_ready = false;
    g_extended_archive_storage = false;
    bool valid = true, compatibility = false;
    std::vector<CodeContract> contracts;
    contracts.reserve(sizeof(freezefix::kCodeIdentities) / sizeof(freezefix::kCodeIdentities[0]));
    for (const auto& identity : freezefix::kCodeIdentities) {
        if (!g_config.monitor && std::strcmp(identity.name, "lock_read") == 0) continue;
        std::vector<std::uint8_t> bytes;
        CodeContract contract;
        IdentityDiagnostic diagnostic;
        const bool accepted = ReadCode(image, identity.rva, identity.length, bytes) &&
                              ValidateIdentity(identity, image.base + identity.rva, bytes, contract, diagnostic);
        if (!accepted || diagnostic.detoured) Log("%s", FormatIdentityDiagnostic(identity, diagnostic).c_str());
        if (!accepted) { valid = false; continue; }
        compatibility = compatibility || diagnostic.detoured;
        contracts.push_back(std::move(contract));
    }
    if (!valid) return false;
    g_code_contracts = std::move(contracts);
    g_extended_archive_storage = compatibility;
    if (compatibility)
        Log("compatibility: verified archive detours retained; extended storage keys are read through the verified vector layout");
    g_contracts_ready = true;
    return true;
}

bool CaptureInstalledHook(void* target, const void* detour, InstalledHook& output) noexcept {
    InstalledHook candidate;
    candidate.entry = reinterpret_cast<std::uintptr_t>(target);
    if (!ReadMemory(candidate.entry, candidate.prefix.data(), candidate.prefix.size()) ||
        candidate.prefix[0] != 0xE9) return false;
    std::int32_t displacement = 0;
    std::memcpy(&displacement, candidate.prefix.data() + 1, sizeof(displacement));
    std::uintptr_t next = 0;
    if (!AddAddress(candidate.entry, candidate.prefix.size(), next)) return false;
    if (displacement >= 0) {
        if (!AddAddress(next, static_cast<std::uint32_t>(displacement), candidate.relay)) return false;
    } else {
        const auto distance = static_cast<std::uint64_t>(-static_cast<std::int64_t>(displacement));
        if (distance > next) return false;
        candidate.relay = next - static_cast<std::uintptr_t>(distance);
    }
    if (!ReadMemory(candidate.relay, candidate.relay_bytes.data(), candidate.relay_bytes.size())) return false;
    constexpr std::array<std::uint8_t, 6> indirect_jump{{0xFF, 0x25, 0, 0, 0, 0}};
    std::uintptr_t destination = 0;
    std::memcpy(&destination, candidate.relay_bytes.data() + indirect_jump.size(), sizeof(destination));
    if (std::memcmp(candidate.relay_bytes.data(), indirect_jump.data(), indirect_jump.size()) != 0 ||
        destination != reinterpret_cast<std::uintptr_t>(detour)) return false;
    candidate.valid = true;
    output = candidate;
    return true;
}

bool InstalledHookUnchanged(const InstalledHook& hook) noexcept {
    if (!hook.valid) return false;
    std::array<std::uint8_t, 5> prefix{};
    std::array<std::uint8_t, 14> relay{};
    return ReadMemory(hook.entry, prefix.data(), prefix.size()) && prefix == hook.prefix &&
           ReadMemory(hook.relay, relay.data(), relay.size()) && relay == hook.relay_bytes;
}

constexpr std::size_t LargestCodeContract() noexcept {
    std::size_t result = 0;
    for (const auto& identity : freezefix::kCodeIdentities)
        if (identity.length > result) result = identity.length;
    return result;
}

bool CodeContractsUnchanged() noexcept {
    if (!g_contracts_ready || g_code_contracts.empty() ||
        (g_config.fix && !InstalledHookUnchanged(g_insert_hook)) ||
        (g_config.monitor && !InstalledHookUnchanged(g_read_hook))) return false;
    std::array<std::uint8_t, LargestCodeContract()> current{};
    for (const auto& contract : g_code_contracts) {
        if (!contract.identity || contract.expected.size() != contract.identity->length ||
            contract.expected.size() > current.size()) return false;
        const bool patched = (g_config.fix && contract.identity->rva == freezefix::kHashInsertRva) ||
                             (g_config.monitor && contract.identity->rva == freezefix::kLockReadRva);
        const std::size_t skip = patched ? g_insert_hook.prefix.size() : 0;
        if (contract.expected.size() <= skip) return false;
        const auto length = contract.expected.size() - skip;
        std::uintptr_t address = 0;
        if (!AddAddress(contract.address, skip, address) || !ReadMemory(address, current.data(), length) ||
            std::memcmp(current.data(), contract.expected.data() + skip, length) != 0) return false;
        for (const auto& evidence : contract.detour_bytes) {
            if (evidence.bytes.empty() || evidence.bytes.size() > current.size() ||
                (evidence.kind == freezefix::detour::ReadKind::Code &&
                 !AccessibleRange(evidence.address, evidence.bytes.size(), true, false)) ||
                !ReadMemory(evidence.address, current.data(), evidence.bytes.size()) ||
                std::memcmp(current.data(), evidence.bytes.data(), evidence.bytes.size()) != 0) return false;
        }
        for (const auto& module : contract.modules)
            if (!DetourModuleStillMapped(module)) return false;
    }
    return true;
}

struct NativeTable {
    std::uint64_t allocator = 0;
    std::uintptr_t entries = 0;
    std::uint32_t capacity = 0, mask = 0, available = 0, last_free = 0;
};
static_assert(sizeof(NativeTable) == 0x20, "verified 1.10.163 table header");
static_assert(offsetof(NativeTable, available) == 0x18, "verified metadata offset");
struct WriterLock { DWORD owner = 0; std::uint32_t state = 0; };
struct CapturedIndex {
    NativeTable table{};
    std::uint32_t count = 0;
    std::uintptr_t keys_address = 0;
    std::vector<archive::Key> keys;
    std::vector<archive::Entry> entries;

    archive::Snapshot view() const noexcept {
        return {entries.data(), table.capacity, keys.data(),
                static_cast<std::uint32_t>(keys.size()), count,
                table.mask, table.available, table.last_free};
    }
};

// The native index stores 256 keys inline. Daytripper4's extended storage keeps
// 0..254 inline and replaces slot 255 with a std::vector<ResourceID>* whose
// elements are indices 255 and above (GetDataFileNameIdEx: extended[i - 255]).
constexpr std::uint32_t kInlineKeys = 255u;

// extended selects the storage contract. Without the archive detours slot 255
// is an ordinary key and the fixed array is contiguous, so a native table with
// 255 members must not be read as if it held a vector pointer.
bool ReadKeys(std::uintptr_t keys_address, std::uint32_t keyCount,
              std::vector<archive::Key>& keys, bool extended) {
    if (!keyCount || keyCount > archive::kMaxNames) return false;
    keys.assign(keyCount, archive::Key{});
    if (!extended) {
        return ReadMemory(keys_address, keys.data(),
                          static_cast<std::size_t>(keyCount) * sizeof(archive::Key));
    }
    const std::uint32_t inlineCount = keyCount < kInlineKeys ? keyCount : kInlineKeys;
    if (inlineCount &&
        !ReadMemory(keys_address, keys.data(),
                    static_cast<std::size_t>(inlineCount) * sizeof(archive::Key))) return false;
    if (keyCount <= kInlineKeys) return true;

    std::uintptr_t slot = 0, vector = 0;
    if (!AddAddress(keys_address, static_cast<std::size_t>(kInlineKeys) * sizeof(archive::Key), slot) ||
        !AccessibleRange(slot, sizeof(std::uintptr_t), false) ||
        !ReadMemory(slot, &vector, sizeof(vector)) || !vector) return false;
    // MSVC std::vector<T>: {first, last, end}. Only first/last are consulted.
    std::array<std::uintptr_t, 3> fields{};
    if (!AccessibleRange(vector, sizeof(fields), false) ||
        !ReadMemory(vector, fields.data(), sizeof(fields))) return false;
    const std::uintptr_t first = fields[0], last = fields[1];
    if (!first || last < first || ((last - first) % sizeof(archive::Key)) != 0) return false;
    const std::uint32_t available = static_cast<std::uint32_t>((last - first) / sizeof(archive::Key));
    const std::uint32_t needed = keyCount - kInlineKeys;
    if (available < needed) return false;
    const std::size_t bytes = static_cast<std::size_t>(needed) * sizeof(archive::Key);
    return AccessibleRange(first, bytes, false) &&
           ReadMemory(first, keys.data() + kInlineKeys, bytes);
}

bool OwnedByCurrentThread(std::uintptr_t self) noexcept {
    std::uintptr_t address = 0;
    WriterLock lock{};
    return AddAddress(self, freezefix::kArchiveWriterOffset, address) &&
           ReadMemory(address, &lock, sizeof(lock)) && lock.owner == GetCurrentThreadId() &&
           lock.state == 0x80000001u;
}

bool CaptureIndex(std::uintptr_t self, std::uint32_t incoming,
                  const archive::Key** keys_reference, CapturedIndex& snapshot) {
    if (self < 0x10 || self % alignof(std::uint64_t) || incoming >= archive::kMaxNames ||
        !OwnedByCurrentThread(self) || !ReadMemory(self, &snapshot.table, sizeof(snapshot.table))) return false;
    std::uintptr_t count_address = 0, keys_address = 0, object_end = 0;
    if (!AddAddress(self, freezefix::kArchiveCountOffset, count_address) ||
        !AddAddress(self, freezefix::kArchiveKeysOffset, keys_address) ||
        !AddAddress(self - 0x10, freezefix::kArchiveObjectExtent, object_end) ||
        !ReadMemory(count_address, &snapshot.count, sizeof(snapshot.count)) || snapshot.count != incoming ||
        !ReadMemory(reinterpret_cast<std::uintptr_t>(keys_reference), &snapshot.keys_address,
                    sizeof(snapshot.keys_address)) || snapshot.keys_address != keys_address) return false;
    const auto capacity = snapshot.table.capacity;
    if (capacity < 2 || capacity > archive::kMaxCapacity || (capacity & (capacity - 1)) ||
        snapshot.table.mask != capacity - 1 || snapshot.table.last_free >= capacity ||
        incoming > capacity || snapshot.table.available != capacity - incoming) return false;
    const std::size_t table_bytes = static_cast<std::size_t>(capacity) * sizeof(archive::Entry);
    if (snapshot.table.entries % alignof(std::uint32_t) ||
        !Disjoint(snapshot.table.entries, table_bytes, self - 0x10, freezefix::kArchiveObjectExtent) ||
        !Disjoint(snapshot.table.entries, table_bytes,
                   reinterpret_cast<std::uintptr_t>(keys_reference), sizeof(*keys_reference)) ||
        !AccessibleRange(snapshot.table.entries, table_bytes, false) ||
        !AccessibleRange(self + offsetof(NativeTable, available), sizeof(std::uint32_t) * 2, false) ||
        !ReadKeys(keys_address, incoming + 1, snapshot.keys, g_extended_archive_storage)) return false;
    snapshot.entries.resize(capacity);
    return ReadMemory(snapshot.table.entries, snapshot.entries.data(), table_bytes) && OwnedByCurrentThread(self);
}

bool SameSnapshot(const CapturedIndex& first, const CapturedIndex& second) noexcept {
    return std::memcmp(&first.table, &second.table, sizeof(NativeTable)) == 0 &&
           first.count == second.count && first.keys_address == second.keys_address &&
           first.keys.size() == second.keys.size() &&
           std::memcmp(first.keys.data(), second.keys.data(),
                       first.keys.size() * sizeof(archive::Key)) == 0 &&
           first.entries.size() == second.entries.size() &&
           std::memcmp(first.entries.data(), second.entries.data(),
                       first.entries.size() * sizeof(archive::Entry)) == 0;
}

const char* ValidationName(archive::Validation validation) noexcept {
    switch (validation) {
    case archive::Validation::Healthy: return "healthy";
    case archive::Validation::Rebuildable: return "links-or-sentinel-allocation";
    case archive::Validation::InvalidShape: return "invalid-shape";
    case archive::Validation::InvalidCount: return "unsupported-count";
    case archive::Validation::InvalidMetadata: return "invalid-metadata";
    case archive::Validation::InvalidMembership: return "incomplete-or-ambiguous-membership";
    case archive::Validation::DuplicateKey: return "duplicate-key";
    }
    return "unknown";
}

bool TryRebuild(std::uintptr_t self, std::uint32_t incoming, const archive::Key** keys_reference) {
    CapturedIndex before;
    if (!CaptureIndex(self, incoming, keys_reference, before)) {
        if (g_extended_archive_storage && incoming >= kInlineKeys) {
            RecordExtendedStorageDecline(self, incoming);
        } else {
            g_declines.fetch_add(1, std::memory_order_relaxed);
            QueueEvent("DECLINED", "caller-layout-owner-or-memory-guard", self, incoming, 0,
                        CapacitySource::Unavailable);
        }
        return false;
    }
    const auto validation = archive::Analyze(before.view());
    if (validation == archive::Validation::Healthy) return false;
    if (validation != archive::Validation::Rebuildable) {
        g_declines.fetch_add(1, std::memory_order_relaxed);
        QueueEvent("DECLINED", ValidationName(validation), self, incoming, before.table.capacity);
        return false;
    }
    std::vector<archive::Entry> staged(before.table.capacity);
    const auto plan = archive::BuildRepair(before.view(), staged.data(), staged.size());
    if (plan.status != archive::BuildStatus::Ready) {
        g_declines.fetch_add(1, std::memory_order_relaxed);
        QueueEvent("DECLINED", "staging-or-verification-failed", self, incoming, before.table.capacity);
        return false;
    }
    CapturedIndex current;
    if (!CaptureIndex(self, incoming, keys_reference, current) || !SameSnapshot(before, current) ||
        !OwnedByCurrentThread(self)) {
        g_declines.fetch_add(1, std::memory_order_relaxed);
        QueueEvent("DECLINED", "snapshot-changed", self, incoming, before.table.capacity);
        return false;
    }
    // Other PostPostLoad listeners may have changed these routines after our
    // installation. Recheck the actual caller/lookup/owner semantics and our own
    // detour plus untouched insert body before making any engine write.
    if (!CodeContractsUnchanged() || !OwnedByCurrentThread(self)) {
        g_declines.fetch_add(1, std::memory_order_relaxed);
        QueueEvent("DECLINED", "code-contract-or-owner-changed", self, incoming, before.table.capacity);
        return false;
    }

    // Commit only to the existing allocation while the original engine writer
    // owns the verified lock. All allocation, reads, and validation are complete.
    // Do not catch access violations and continue after a partial commit.
    std::memcpy(reinterpret_cast<void*>(before.table.entries), staged.data(),
                staged.size() * sizeof(archive::Entry));
    const std::uint32_t metadata[]{plan.available, plan.lastFree};
    std::memcpy(reinterpret_cast<void*>(self + offsetof(NativeTable, available)), metadata, sizeof(metadata));
    g_rebuilds.fetch_add(1, std::memory_order_relaxed);
    QueueEvent("REBUILT", "all-existing-members-preserved-and-new-member-inserted", self, incoming,
                before.table.capacity);
    // AddDataFile increments the name count after this successful return.
    return true;
}

bool HookInsert(void* self, std::uint32_t incoming, const archive::Key** keys_reference) {
    const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    if (g_active.load(std::memory_order_acquire) &&
        caller == g_image_base + freezefix::kArchiveInsertReturnRva) {
        try {
            if (TryRebuild(reinterpret_cast<std::uintptr_t>(self), incoming, keys_reference)) return true;
        } catch (...) {
            // C++ allocation/diagnostic failures occur before commit. /EHsc does
            // not turn an access violation into a recoverable C++ exception.
            g_declines.fetch_add(1, std::memory_order_relaxed);
            QueueEvent("DECLINED", "exception-before-commit", reinterpret_cast<std::uintptr_t>(self), incoming, 0,
                        CapacitySource::Unavailable);
        }
    }
    // Do not fabricate failure: the caller's false-return path grows the table.
    // Unsupported states keep native behavior, including the original hang.
    return g_original_insert(self, incoming, keys_reference);
}

void HookLockRead(void* self) {
    if (!g_active.load(std::memory_order_acquire)) { g_original_lock_read(self); return; }
    const auto token = g_waits.begin(GetCurrentThreadId(), reinterpret_cast<std::uintptr_t>(self), GetTickCount64());
    if (!token) g_dropped_waits.fetch_add(1, std::memory_order_relaxed);
    struct EndRecord {
        freezefix::Token token;
        ~EndRecord() { g_waits.end(token); }
    } end{token};
    g_original_lock_read(self);
}

bool FormatEvent(const Event& event, char* output, std::size_t size) noexcept {
    if (!output || !size) return false;
    char capacity[16]{};
    const char* source = "unavailable";
    if (event.capacity_source == CapacitySource::Unavailable) {
        std::snprintf(capacity, sizeof(capacity), "unavailable");
    } else {
        std::snprintf(capacity, sizeof(capacity), "%u", static_cast<unsigned>(event.capacity));
        source = event.capacity_source == CapacitySource::RawHeader
            ? "raw-header+0x10-unvalidated" : "validated-snapshot";
    }
    char header[160]{};
    if (event.header_requested) {
        if (!event.header.readable) {
            std::snprintf(header, sizeof(header), " raw_header=unavailable");
        } else {
            const auto& word = event.header.words;
            std::snprintf(header, sizeof(header),
                " raw_header_u32_00_1C=[%08X,%08X,%08X,%08X,%08X,%08X,%08X,%08X]",
                static_cast<unsigned>(word[0]), static_cast<unsigned>(word[1]),
                static_cast<unsigned>(word[2]), static_cast<unsigned>(word[3]),
                static_cast<unsigned>(word[4]), static_cast<unsigned>(word[5]),
                static_cast<unsigned>(word[6]), static_cast<unsigned>(word[7]));
        }
    }
    char sampling[96]{};
    if (event.reason_occurrence)
        std::snprintf(sampling, sizeof(sampling), " reason_occurrence=%llu reporting=powers-of-two",
                      static_cast<unsigned long long>(event.reason_occurrence));
    const int written = std::snprintf(output, size,
        "%s tid=%lu table=%p incoming=%u capacity=%s capacity_source=%s reason=%s%s%s",
        event.kind ? event.kind : "UNKNOWN", static_cast<unsigned long>(event.thread_id),
        reinterpret_cast<void*>(event.table), static_cast<unsigned>(event.index), capacity, source,
        event.reason ? event.reason : "unknown", header, sampling);
    return written >= 0 && static_cast<std::size_t>(written) < size;
}

void DrainEvents() {
    PSLIST_ENTRY entry = InterlockedFlushSList(&g_pending_events);
    while (entry) {
        auto* node = reinterpret_cast<EventNode*>(entry);
        entry = entry->Next;
        const Event event = node->event;
        char line[768]{};
        if (FormatEvent(event, line, sizeof(line))) Log("%s", line);
        else Log("event formatting unavailable tid=%lu table=%p incoming=%u",
                 static_cast<unsigned long>(event.thread_id), reinterpret_cast<void*>(event.table),
                 static_cast<unsigned>(event.index));
        InterlockedPushEntrySList(&g_free_events, &node->link);
    }
}

DWORD WINAPI Watchdog(LPVOID) {
    std::uint64_t last_beat = GetTickCount64(), reported_waits = 0;
    for (;;) {
        const DWORD wait = WaitForSingleObject(g_stop_event, g_config.poll_ms);
        if (wait != WAIT_TIMEOUT) break;
        DrainEvents();
        if (g_config.monitor) {
            for (std::size_t i = 0; i < g_waits.capacity(); ++i) {
                freezefix::Snapshot snapshot;
                if (!g_waits.try_snapshot(i, snapshot) || snapshot.reported) continue;
                const auto age = freezefix::elapsed_ms(GetTickCount64(), snapshot.since_ms);
                if (age < g_config.stall_ms || !g_waits.try_mark_reported(snapshot.token)) continue;
                ++reported_waits;
                Log("LONG_WAIT tid=%lu lock_address=%p observed_ms=%llu action=none; this is not proof of deadlock",
                    static_cast<unsigned long>(snapshot.thread_id), reinterpret_cast<void*>(snapshot.object),
                    static_cast<unsigned long long>(age));
            }
        }
        const auto now = GetTickCount64();
        if (freezefix::elapsed_ms(now, last_beat) >= 60000) {
            last_beat = now;
            Log("heartbeat rebuilds=%llu declined=%llu extended_declines=%llu highest_extended_incoming=%u suppressed_extended_events=%llu reported_waits=%llu dropped_events=%llu untracked_waits=%llu",
                static_cast<unsigned long long>(g_rebuilds.load()), static_cast<unsigned long long>(g_declines.load()),
                static_cast<unsigned long long>(g_extended_declines.load()),
                static_cast<unsigned>(g_highest_extended_incoming.load()),
                static_cast<unsigned long long>(g_suppressed_extended_events.load()),
                static_cast<unsigned long long>(reported_waits), static_cast<unsigned long long>(g_dropped_events.load()),
                static_cast<unsigned long long>(g_dropped_waits.load()));
        }
    }
    DrainEvents();
    return 0;
}

struct InstallOperations {
    void* insert = nullptr;
    void* lock_read = nullptr;
    bool insert_created = false, read_created = false;
    bool insert_enabled = false, read_enabled = false;

    bool initialize() {
        InitializeSListHead(&g_free_events);
        InitializeSListHead(&g_pending_events);
        for (auto& event : g_events) InterlockedPushEntrySList(&g_free_events, &event.link);
        return MH_Initialize() == MH_OK;
    }
    bool create_hook() {
        if (g_config.fix) {
            if (MH_CreateHook(insert, &HookInsert, reinterpret_cast<void**>(&g_original_insert)) != MH_OK) return false;
            insert_created = true;
        }
        if (g_config.monitor) {
            if (MH_CreateHook(lock_read, &HookLockRead, reinterpret_cast<void**>(&g_original_lock_read)) != MH_OK) return false;
            read_created = true;
        }
        return true;
    }
    bool start_watchdog() {
        g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!g_stop_event) return false;
        g_watchdog = CreateThread(nullptr, 0, &Watchdog, nullptr, 0, nullptr);
        if (!g_watchdog) { CloseHandle(g_stop_event); g_stop_event = nullptr; return false; }
        return true;
    }
    bool enable_hook() {
        if (insert_created) {
            if (MH_EnableHook(insert) != MH_OK) return false;
            insert_enabled = true;
            if (!CaptureInstalledHook(insert, reinterpret_cast<const void*>(&HookInsert), g_insert_hook)) return false;
        }
        if (read_created) {
            if (MH_EnableHook(lock_read) != MH_OK) return false;
            read_enabled = true;
            if (!CaptureInstalledHook(lock_read, reinterpret_cast<const void*>(&HookLockRead), g_read_hook)) return false;
        }
        return true;
    }
    bool any_hook_enabled() const noexcept { return insert_enabled || read_enabled; }
    bool stop_watchdog() {
        if (!g_watchdog) return true;
        if (!SetEvent(g_stop_event) || WaitForSingleObject(g_watchdog, 2000) != WAIT_OBJECT_0) return false;
        CloseHandle(g_watchdog); g_watchdog = nullptr;
        CloseHandle(g_stop_event); g_stop_event = nullptr;
        return true;
    }
    bool remove_hook() {
        if (any_hook_enabled()) return false;
        bool ok = true;
        if (read_created) {
            const bool removed = MH_RemoveHook(lock_read) == MH_OK;
            if (removed) read_created = false;
            ok = removed && ok;
        }
        if (insert_created) {
            const bool removed = MH_RemoveHook(insert) == MH_OK;
            if (removed) insert_created = false;
            ok = removed && ok;
        }
        return ok;
    }
    bool uninitialize() { return !any_hook_enabled() && MH_Uninitialize() == MH_OK; }
};

// --- Native key-access corrections -------------------------------------------
//
// Daytripper4 keeps keys 0..254 inline and moves 255 and above into a vector
// reached through fixed slot 255. The engine's insertion and collision-loop
// code still computes parent + 0x1030 + index * 12, which is wrong for extended
// indices. These corrections replace one instruction window each with a call to
// a stub that asks for the real key address and reproduces what it displaced.

extern "C" const void* FreezeFixKeyAddress(const void* keyArray, std::uint32_t index) {
    const auto* base = static_cast<const std::uint8_t*>(keyArray);
    if (index < kInlineKeys)
        return base + static_cast<std::size_t>(index) * sizeof(archive::Key);
    std::uintptr_t vector = 0;
    std::memcpy(&vector, base + kInlineKeys * sizeof(archive::Key), sizeof(vector));
    if (!vector) return base;
    std::array<std::uintptr_t, 3> fields{};
    std::memcpy(fields.data(), reinterpret_cast<const void*>(vector), sizeof(fields));
    const std::uintptr_t first = fields[0], last = fields[1];
    if (!first || last < first) return base;
    const std::uint32_t available =
        static_cast<std::uint32_t>((last - first) / sizeof(archive::Key));
    const std::uint32_t wanted = index - kInlineKeys;
    if (wanted >= available) return base;
    return reinterpret_cast<const void*>(first + wanted * sizeof(archive::Key));
}

void* AllocateStubNear(std::uintptr_t target, std::size_t size) {
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    const auto granularity = static_cast<std::uintptr_t>(info.dwAllocationGranularity);
    for (std::uintptr_t delta = granularity; delta < 0x40000000ull; delta <<= 1) {
        for (int direction = -1; direction <= 1; direction += 2) {
            const auto offset = static_cast<std::int64_t>(delta) * direction;
            const auto hint = static_cast<std::int64_t>(target) + offset;
            if (hint <= 0) continue;
            auto* memory = VirtualAlloc(reinterpret_cast<void*>(
                                            static_cast<std::uintptr_t>(hint) & ~(granularity - 1)),
                                        size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!memory) continue;
            const auto distance = reinterpret_cast<std::uintptr_t>(memory) > target
                                      ? reinterpret_cast<std::uintptr_t>(memory) - target
                                      : target - reinterpret_cast<std::uintptr_t>(memory);
            if (distance < 0x7FFF0000ull) return memory;
            VirtualFree(memory, 0, MEM_RELEASE);
        }
    }
    return nullptr;
}

// Installs one call-stub window. expected is the contract copy that must be
// updated so later revalidation accepts the patched bytes.
bool InstallNativePatch(std::uintptr_t site, const std::uint8_t* original, std::size_t length,
                        const std::vector<std::uint8_t>& stub, std::uint8_t* expected) {
    std::array<std::uint8_t, 16> current{};
    if (!length || length > current.size() || length < 5) return false;
    if (!ReadMemory(site, current.data(), length) ||
        std::memcmp(current.data(), original, length) != 0) return false;
    auto* memory = static_cast<std::uint8_t*>(AllocateStubNear(site, stub.size()));
    if (!memory) return false;
    std::memcpy(memory, stub.data(), stub.size());
    FlushInstructionCache(GetCurrentProcess(), memory, stub.size());
    const auto displacement = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(memory)) -
                              static_cast<std::int64_t>(site + 5);
    if (displacement < INT32_MIN || displacement > INT32_MAX) return false;
    std::array<std::uint8_t, 16> patch{};
    patch[0] = 0xE8;
    const auto relative = static_cast<std::int32_t>(displacement);
    std::memcpy(patch.data() + 1, &relative, sizeof(relative));
    for (std::size_t i = 5; i < length; ++i) patch[i] = 0x90;
    DWORD previous = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(site), length, PAGE_EXECUTE_READWRITE, &previous))
        return false;
    std::memcpy(reinterpret_cast<void*>(site), patch.data(), length);
    DWORD ignored = 0;
    VirtualProtect(reinterpret_cast<void*>(site), length, previous, &ignored);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(site), length);
    if (expected) std::memcpy(expected, patch.data(), length);
    return true;
}

struct CorrectionResult {
    bool lookup_loop = false;
    bool insert_incoming = false;
    bool insert_displaced = false;
};

CorrectionResult InstallNativeCorrections(std::uintptr_t base) {
    CorrectionResult result;
    const auto helper = reinterpret_cast<std::uintptr_t>(&FreezeFixKeyAddress);
    for (auto& contract : g_code_contracts) {
        if (!contract.identity) continue;
        const auto rva = contract.identity->rva;
        const auto apply = [&](std::uintptr_t site_rva, const std::uint8_t* original,
                               std::size_t length, const std::vector<std::uint8_t>& stub) {
            if (site_rva < rva || site_rva - rva + length > contract.expected.size()) return false;
            const auto offset = static_cast<std::size_t>(site_rva - rva);
            return InstallNativePatch(base + site_rva, original, length, stub,
                                      contract.expected.data() + offset);
        };
        if (rva == 0x1B78AF0) {
            result.lookup_loop = apply(freezefix::native::kLookupLoopRva,
                                       freezefix::native::kLookupLoopOriginal.data(),
                                       freezefix::native::kLookupLoopOriginal.size(),
                                       freezefix::native::BuildLookupStub(helper));
        } else if (rva == 0x1B772F0) {
            result.insert_incoming = apply(freezefix::native::kInsertIncomingRva,
                                           freezefix::native::kInsertIncomingOriginal.data(),
                                           freezefix::native::kInsertIncomingOriginal.size(),
                                           freezefix::native::BuildIncomingStub(helper));
            result.insert_displaced = apply(freezefix::native::kInsertDisplacedRva,
                                            freezefix::native::kInsertDisplacedOriginal.data(),
                                            freezefix::native::kInsertDisplacedOriginal.size(),
                                            freezefix::native::BuildDisplacedStub(helper));
        }
    }
    return result;
}

void Install() {
    if (g_install_attempted.exchange(true)) return;
    if (!g_config.enabled || (!g_config.fix && !g_config.monitor)) {
        Log("disabled by configuration; no hooks installed");
        return;
    }
    const auto path = std::filesystem::path(g_directory) / L"version-1-10-163-0.bin";
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error) { Log("INERT address library unavailable"); return; }
    std::ifstream stream(path, std::ios::binary);
    freezefix::Addresses targets;
    const auto status = freezefix::read_address_library(stream, size, targets);
    if (status != freezefix::AddressError::none) {
        Log("INERT address library rejected: %s", freezefix::address_error_name(status));
        return;
    }
    Image image;
    if (!ReadImage(image)) { Log("INERT invalid executable image"); return; }
    if (!ValidateCode(image)) return;
    g_image_base = image.base;

    // Extended storage is the only configuration where the engine's fixed-array
    // key arithmetic is wrong, so the corrections are installed only there.
    CorrectionResult corrections;
    if (g_extended_archive_storage) {
        corrections = InstallNativeCorrections(image.base);
        Log("native corrections lookup_loop=%d insert_incoming=%d insert_displaced=%d",
            corrections.lookup_loop ? 1 : 0, corrections.insert_incoming ? 1 : 0,
            corrections.insert_displaced ? 1 : 0);
        if (!corrections.lookup_loop || !corrections.insert_incoming || !corrections.insert_displaced)
            Log("native corrections incomplete; the rebuild remains the only recovery path");
    }

    // Keep callback/trampoline code resident even if a failed rollback leaves a
    // pass-through hook. These resources intentionally have process lifetime.
    HMODULE pinned = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                           reinterpret_cast<LPCWSTR>(&Install), &pinned)) {
        Log("INERT could not pin plugin lifetime");
        return;
    }
    InstallOperations operations;
    operations.insert = reinterpret_cast<void*>(image.base + targets.hash_insert);
    operations.lock_read = reinterpret_cast<void*>(image.base + targets.lock_read);
    const auto installed = freezefix::install_observer(operations);
    if (!installed) {
        g_active.store(false, std::memory_order_release);
        Log("INERT installation failed stage=%u rollback_complete=%d; no recovery enabled",
            static_cast<unsigned>(installed.stage), installed.rollback_ok ? 1 : 0);
        if (operations.any_hook_enabled())
            Log("pass-through hooks and all associated resources retained for process lifetime; trampolines not freed");
        return;
    }
    g_active.store(true, std::memory_order_release);
    Log("installed constrained_archive_rebuild=%d passive_wait_monitor=%d stall_ms=%lu poll_ms=%lu repair_storage=verified-inline-and-extended-keys incoming_limit_exclusive=%u extended_storage_repair=%d",
        g_config.fix ? 1 : 0, g_config.monitor ? 1 : 0, g_config.stall_ms, g_config.poll_ms,
        archive::kMaxNames, g_extended_archive_storage ? 1 : 0);
}

void OnMessage(F4SEMessagingInterface::Message* message) {
    if (!message || message->type != F4SEMessagingInterface::kMessage_PostPostLoad) return;
    try { Install(); }
    catch (...) { Log("INERT exception during installation; recovery remains disabled"); }
}
} // namespace

extern "C" __declspec(dllexport) bool F4SEPlugin_Query(const F4SEInterface* f4se, PluginInfo* info) {
    if (!f4se || !info) return false;
    info->infoVersion = PluginInfo::kInfoVersion;
    info->name = "FreezeFixF4";
    info->version = 20002;
    if (f4se->isEditor || f4se->runtimeVersion != kRuntime) return false;
    g_plugin = f4se->GetPluginHandle();
    return g_plugin != kPluginHandle_Invalid;
}

extern "C" __declspec(dllexport) bool F4SEPlugin_Load(const F4SEInterface* f4se) {
    if (!f4se || f4se->isEditor || f4se->runtimeVersion != kRuntime) return false;
    if (!InitializePaths()) return true;
    OpenLog();
    ReadConfig();
    Log("FreezeFixF4 %s runtime=0x%08X f4se=0x%08X", kVersion, f4se->runtimeVersion, f4se->f4seVersion);
    auto* messaging = static_cast<F4SEMessagingInterface*>(f4se->QueryInterface(kInterface_Messaging));
    if (!messaging || messaging->interfaceVersion < F4SEMessagingInterface::kInterfaceVersion ||
        !messaging->RegisterListener(g_plugin, "F4SE", &OnMessage)) {
        Log("INERT messaging registration failed");
    }
    return true;
}
