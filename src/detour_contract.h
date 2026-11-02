#pragma once

// Narrow identity compatibility for explicitly listed, instruction-aligned
// patch windows. A module-owned endpoint identifies where a detour goes; it
// does not prove that the replacement preserves the engine's semantics.
// Normalize only after successful resolution, and require the full native
// SHA-256 to match after normalization. Never normalize live executable memory.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace freezefix {
namespace detour {

constexpr std::size_t kMaxHops = 8;
constexpr std::size_t kMaxWindow = 32;
constexpr std::size_t kMaxRead = 128;
constexpr std::size_t kNoDifference = (std::numeric_limits<std::size_t>::max)();

enum class StubKind { None, AddArchive, AddStream, AddName, LookupName };
enum class ReadKind { Code, Data };
enum class WindowState { Native, Detoured, Rejected };
enum class Reason {
    Accepted,
    Native,
    InvalidAddress,
    OutOfBounds,
    UnsupportedPatch,
    AddressOverflow,
    Unreadable,
    Cycle,
    HopLimit,
    UnsupportedRelay,
    InvalidStub,
    ReturnMismatch
};

inline const char* ReasonName(Reason reason) noexcept {
    switch (reason) {
    case Reason::Accepted: return "loaded-module-endpoint";
    case Reason::Native: return "native-window";
    case Reason::InvalidAddress: return "invalid-address";
    case Reason::OutOfBounds: return "window-out-of-bounds";
    case Reason::UnsupportedPatch: return "unsupported-patch-bytes";
    case Reason::AddressOverflow: return "address-overflow";
    case Reason::Unreadable: return "unreadable-or-nonexecutable-code";
    case Reason::Cycle: return "cyclic-detour-chain";
    case Reason::HopLimit: return "detour-hop-limit";
    case Reason::UnsupportedRelay: return "unrecognized-anonymous-code";
    case Reason::InvalidStub: return "known-stub-bytes-mismatch";
    case Reason::ReturnMismatch: return "stub-return-target-mismatch";
    }
    return "unknown";
}

struct PatchWindow {
    std::size_t offset = 0;
    std::size_t length = 0;
    std::array<std::uint8_t, kMaxWindow> original{};
    StubKind stub = StubKind::None;
};

struct WindowResult {
    WindowState state = WindowState::Rejected;
    Reason reason = Reason::OutOfBounds;
    std::uintptr_t target = 0;
    std::uintptr_t continuation = 0;
};

struct Resolution {
    bool accepted = false;
    std::uintptr_t endpoint = 0;
    Reason reason = Reason::InvalidAddress;
    std::size_t hops = 0;
};

inline bool CheckedRelativeTarget(std::uintptr_t address, std::size_t instruction_length,
                                  std::int64_t displacement, std::uintptr_t& target) noexcept {
    const auto maximum = (std::numeric_limits<std::uintptr_t>::max)();
    if (instruction_length > maximum - address) return false;
    const auto next = address + instruction_length;
    if (displacement >= 0) {
        const auto distance = static_cast<std::uint64_t>(displacement);
        if (distance > maximum - next) return false;
        target = next + static_cast<std::uintptr_t>(distance);
    } else {
        // Avoid negating INT64_MIN.
        const auto distance = static_cast<std::uint64_t>(-(displacement + 1)) + 1u;
        if (distance > next) return false;
        target = next - static_cast<std::uintptr_t>(distance);
    }
    return true;
}

namespace detail {

inline std::uint32_t U32(const std::uint8_t* bytes) noexcept {
    std::uint32_t result = 0;
    for (unsigned i = 0; i < 4; ++i) result |= static_cast<std::uint32_t>(bytes[i]) << (8u * i);
    return result;
}

inline std::int64_t I32(const std::uint8_t* bytes) noexcept {
    const std::uint32_t value = U32(bytes);
    return value & 0x80000000u ? static_cast<std::int64_t>(value) - 0x100000000LL : value;
}

inline std::uint64_t U64(const std::uint8_t* bytes) noexcept {
    std::uint64_t result = 0;
    for (unsigned i = 0; i < 8; ++i) result |= static_cast<std::uint64_t>(bytes[i]) << (8u * i);
    return result;
}

inline bool Address64(const std::uint8_t* bytes, std::uintptr_t& address) noexcept {
    const auto value = U64(bytes);
    if constexpr (sizeof(std::uintptr_t) < sizeof(std::uint64_t)) {
        if (value > (std::numeric_limits<std::uintptr_t>::max)()) return false;
    }
    address = static_cast<std::uintptr_t>(value);
    return address != 0;
}

inline bool ValidWindow(const PatchWindow& window, std::size_t size) noexcept {
    return window.length >= 5 && window.length <= window.original.size() &&
           window.offset <= size && window.length <= size - window.offset;
}

// Exact Xbyak 7.28 encodings emitted by Daytripper4 v1.4.9's MIT-licensed
// Archive2IndexHook.cpp at 9be6356ae34bae9094f82e3f69c87e18c9f5fb75.
// Only the helper and return imm64 fields vary. These are whole straight-line
// stubs, not patterns searched inside arbitrary executable data.
inline constexpr std::uint8_t kAddArchive[]{
    0x48,0x89,0xD3,0x4C,0x89,0xC5,0x48,0x89,0xF9,0x89,0xF2,0x48,0xB8,
    0,0,0,0,0,0,0,0,0xFF,0xD0,0x48,0x89,0xC1,0x48,0x89,0xDA,0x48,0xB8,
    0,0,0,0,0,0,0,0,0xFF,0xE0
};
inline constexpr std::uint8_t kAddStream[]{
    0x48,0x89,0xF9,0x89,0xF2,0x48,0xB8,0,0,0,0,0,0,0,0,0xFF,0xD0,
    0x48,0x8B,0x0B,0x48,0x89,0xC2,0x48,0x8B,0x01,0x49,0xB8,
    0,0,0,0,0,0,0,0,0x41,0xFF,0xE0
};
inline constexpr std::uint8_t kAddName[]{
    0x48,0x89,0xF9,0x89,0xF2,0x48,0xB8,0,0,0,0,0,0,0,0,0xFF,0xD0,
    0x48,0x8D,0x90,0xD0,0xEF,0xFF,0xFF,0x48,0xB8,
    0,0,0,0,0,0,0,0,0xFF,0xE0
};
inline constexpr std::uint8_t kLookupName[]{
    0x50,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x48,0x83,0xEC,0x20,
    0x4C,0x89,0xD9,0x44,0x89,0xCA,0x48,0xB8,0,0,0,0,0,0,0,0,0xFF,0xD0,
    0x48,0x83,0xC4,0x20,0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,
    0x4C,0x8D,0x80,0xD0,0xEF,0xFF,0xFF,0x58,0x48,0xB9,
    0,0,0,0,0,0,0,0,0xFF,0xE1
};

struct StubTemplate {
    const std::uint8_t* bytes = nullptr;
    std::size_t length = 0;
    std::size_t helper = 0;
    std::size_t continuation = 0;
};

inline StubTemplate Template(StubKind kind) noexcept {
    switch (kind) {
    case StubKind::AddArchive: return {kAddArchive, sizeof(kAddArchive), 13, 31};
    case StubKind::AddStream: return {kAddStream, sizeof(kAddStream), 7, 28};
    case StubKind::AddName: return {kAddName, sizeof(kAddName), 7, 26};
    case StubKind::LookupName: return {kLookupName, sizeof(kLookupName), 21, 53};
    case StubKind::None: return {};
    }
    return {};
}

template<class Read>
bool ReadBytes(Read& read, std::uintptr_t address, void* output, std::size_t length, ReadKind kind) {
    return address != 0 && length != 0 && length <= kMaxRead &&
           length - 1 <= (std::numeric_limits<std::uintptr_t>::max)() - address &&
           read(address, output, length, kind);
}

} // namespace detail

inline WindowResult ParseWindow(const std::uint8_t* actual, std::size_t size,
                                std::uintptr_t function_address, const PatchWindow& window) noexcept {
    WindowResult result;
    if (!actual || !function_address || !detail::ValidWindow(window, size)) return result;
    std::uintptr_t site = 0;
    if (!CheckedRelativeTarget(function_address, window.offset, 0, site) ||
        !CheckedRelativeTarget(site, window.length, 0, result.continuation)) {
        result.reason = Reason::AddressOverflow;
        return result;
    }
    const auto* patch = actual + window.offset;
    if (std::memcmp(patch, window.original.data(), window.length) == 0) {
        result.state = WindowState::Native;
        result.reason = Reason::Native;
        return result;
    }
    if (patch[0] != 0xE9) { result.reason = Reason::UnsupportedPatch; return result; }
    // A five-byte E9 may leave the original tail untouched, or overwrite a
    // contiguous prefix of that tail with literal 90 padding. No other change
    // is ignored, even inside this explicitly allowed window.
    bool padding = true;
    for (std::size_t i = 5; i < window.length; ++i) {
        if (padding && patch[i] == 0x90) continue;
        padding = false;
        if (patch[i] != window.original[i]) {
            result.reason = Reason::UnsupportedPatch;
            return result;
        }
    }
    if (!CheckedRelativeTarget(site, 5, detail::I32(patch + 1), result.target) || !result.target) {
        result.reason = Reason::AddressOverflow;
        return result;
    }
    result.state = WindowState::Detoured;
    result.reason = Reason::Accepted;
    return result;
}

// The caller must resolve and accept the detour first. This operation is only
// for a private validation copy; acceptance still requires the full native hash.
inline bool NormalizePatch(std::uint8_t* copy, std::size_t size, const PatchWindow& window) noexcept {
    if (!copy || !detail::ValidWindow(window, size)) return false;
    std::memcpy(copy + window.offset, window.original.data(), window.length);
    return true;
}

// read(address, output, length, kind) must check readable bounds, require
// executable memory for Code, and retain every observed byte for later equality
// checks. Data is used only for FF25's eight-byte pointer cell. module(address)
// accepts only an executable endpoint inside a loaded module; its adapter pins
// that module and records its identity/RVA. Callbacks may propagate allocation
// failures during installation; this resolver does not swallow them.
template<class Read, class Module>
Resolution Resolve(std::uintptr_t target, std::uintptr_t continuation, StubKind stub,
                   Read&& read, Module&& module) {
    std::array<std::uintptr_t, kMaxHops> visited{};
    for (std::size_t hops = 0; ; ++hops) {
        if (!target) return {false, target, Reason::InvalidAddress, hops};
        if (module(target)) return {true, target, Reason::Accepted, hops};
        for (std::size_t i = 0; i < hops && i < visited.size(); ++i)
            if (visited[i] == target) return {false, target, Reason::Cycle, hops};
        if (hops == kMaxHops) return {false, target, Reason::HopLimit, hops};
        visited[hops] = target;

        std::uint8_t opcode = 0;
        if (!detail::ReadBytes(read, target, &opcode, 1, ReadKind::Code))
            return {false, target, Reason::Unreadable, hops};
        if (opcode == 0xE9) {
            std::array<std::uint8_t, 5> jump{};
            if (!detail::ReadBytes(read, target, jump.data(), jump.size(), ReadKind::Code))
                return {false, target, Reason::Unreadable, hops};
            if (jump[0] != 0xE9) return {false, target, Reason::UnsupportedRelay, hops};
            std::uintptr_t next = 0;
            if (!CheckedRelativeTarget(target, jump.size(), detail::I32(jump.data() + 1), next))
                return {false, target, Reason::AddressOverflow, hops};
            target = next;
            continue;
        }
        if (opcode == 0xFF) {
            std::array<std::uint8_t, 6> jump{};
            if (!detail::ReadBytes(read, target, jump.data(), jump.size(), ReadKind::Code))
                return {false, target, Reason::Unreadable, hops};
            if (jump[0] != 0xFF || jump[1] != 0x25)
                return {false, target, Reason::UnsupportedRelay, hops};
            std::uintptr_t pointer = 0, next = 0;
            if (!CheckedRelativeTarget(target, jump.size(), detail::I32(jump.data() + 2), pointer))
                return {false, target, Reason::AddressOverflow, hops};
            std::array<std::uint8_t, 8> value{};
            if (!detail::ReadBytes(read, pointer, value.data(), value.size(), ReadKind::Data))
                return {false, target, Reason::Unreadable, hops};
            if (!detail::Address64(value.data(), next))
                return {false, target, Reason::InvalidAddress, hops};
            target = next;
            continue;
        }
        if (opcode == 0x48) {
            std::array<std::uint8_t, 12> jump{};
            if (!detail::ReadBytes(read, target, jump.data(), jump.size(), ReadKind::Code))
                return {false, target, Reason::Unreadable, hops};
            if (jump[0] == 0x48 && jump[1] == 0xB8 && jump[10] == 0xFF && jump[11] == 0xE0) {
                std::uintptr_t next = 0;
                if (!detail::Address64(jump.data() + 2, next))
                    return {false, target, Reason::InvalidAddress, hops};
                target = next;
                continue;
            }
        }

        const auto pattern = detail::Template(stub);
        if (!pattern.bytes) return {false, target, Reason::UnsupportedRelay, hops};
        std::array<std::uint8_t, kMaxRead> bytes{};
        if (!detail::ReadBytes(read, target, bytes.data(), pattern.length, ReadKind::Code))
            return {false, target, Reason::Unreadable, hops};
        for (std::size_t i = 0; i < pattern.length; ++i) {
            const bool immediate = (i >= pattern.helper && i - pattern.helper < 8) ||
                                   (i >= pattern.continuation && i - pattern.continuation < 8);
            if (!immediate && bytes[i] != pattern.bytes[i])
                return {false, target, Reason::InvalidStub, hops};
        }
        std::uintptr_t next = 0, back = 0;
        if (!detail::Address64(bytes.data() + pattern.helper, next) ||
            !detail::Address64(bytes.data() + pattern.continuation, back))
            return {false, target, Reason::InvalidAddress, hops};
        if (back != continuation) return {false, target, Reason::ReturnMismatch, hops};
        // The source emits one call-and-return stub at each patch site. Its
        // helper may use jump relays, but another such stub would introduce a
        // different call/return path and is outside this narrow contract.
        stub = StubKind::None;
        target = next;
    }
}

// Diagnostic metadata only. This is the finalized zlib-compatible CRC32 of one
// additional byte, starting with previous=0 for the empty prefix. Full SHA-256,
// never CRC32, remains the executable identity acceptance criterion.
constexpr std::uint32_t Crc32Step(std::uint32_t previous, std::uint8_t byte) noexcept {
    std::uint32_t state = (previous ^ 0xFFFFFFFFu) ^ byte;
    for (unsigned bit = 0; bit < 8; ++bit)
        state = (state >> 1) ^ ((state & 1u) ? 0xEDB88320u : 0u);
    return state ^ 0xFFFFFFFFu;
}

// Reference element i is CRC32(reference[0..i]), with no empty-prefix element.
// At the first unequal input byte the preceding CRC states are identical, and
// the one-byte CRC update is injective, so that first offset cannot be hidden by
// a later multi-byte CRC collision. Unknown shapes return kNoDifference too.
inline std::size_t FirstDifference(const std::uint8_t* actual, std::size_t length,
                                   const std::uint32_t* reference, std::size_t reference_count) noexcept {
    if (!actual || !reference || length != reference_count) return kNoDifference;
    std::uint32_t crc = 0;
    for (std::size_t i = 0; i < length; ++i) {
        crc = Crc32Step(crc, actual[i]);
        if (crc != reference[i]) return i;
    }
    return kNoDifference;
}

} // namespace detour
} // namespace freezefix
