#pragma once

#include <cstddef>
#include <cstdint>
#include <istream>
#include <limits>

namespace freezefix {

inline constexpr std::uint64_t kLockReadId = 1573164;
inline constexpr std::uint64_t kHashInsertId = 1541972;
inline constexpr std::uint64_t kLockReadRva = 0x1B10930;
inline constexpr std::uint64_t kHashInsertRva = 0x1B772F0;
inline constexpr std::uint64_t kMaxAddressCount = 4'000'000;

struct Addresses {
    std::uint64_t lock_read = 0;
    std::uint64_t hash_insert = 0;
};

enum class AddressError {
    none,
    io,
    invalid_size,
    invalid_count,
    unsorted_ids,
    missing_required_id,
    unexpected_rva,
};

inline const char* address_error_name(AddressError error) noexcept {
    switch (error) {
    case AddressError::none: return "none";
    case AddressError::io: return "read-failed";
    case AddressError::invalid_size: return "invalid-file-size";
    case AddressError::invalid_count: return "invalid-entry-count";
    case AddressError::unsorted_ids: return "duplicate-or-unsorted-ids";
    case AddressError::missing_required_id: return "missing-required-id";
    case AddressError::unexpected_rva: return "unexpected-target-rva";
    }
    return "unknown";
}

namespace detail {
inline bool read_u64(std::istream& input, std::uint64_t& result) {
    unsigned char bytes[8]{};
    if (!input.read(reinterpret_cast<char*>(bytes), sizeof(bytes))) return false;
    result = 0;
    for (unsigned i = 0; i < 8; ++i)
        result |= static_cast<std::uint64_t>(bytes[i]) << (i * 8);
    return true;
}
} // namespace detail

// The original Fallout 4 address library is a little-endian count followed by
// sorted {id, RVA} pairs. Keep only the two verified targets, not a large mutable
// map. Publish output only after the entire file passes validation.
inline AddressError read_address_library(
    std::istream& input, std::uint64_t file_size, Addresses& output) {
    output = {};
    if (file_size < 8 || (file_size - 8) % 16 != 0)
        return AddressError::invalid_size;

    std::uint64_t count = 0;
    if (!detail::read_u64(input, count)) return AddressError::io;
    if (count == 0 || count > kMaxAddressCount) return AddressError::invalid_count;
    if (file_size != 8 + count * 16) return AddressError::invalid_size;

    Addresses candidate{};
    std::uint64_t previous = 0;
    for (std::uint64_t i = 0; i < count; ++i) {
        std::uint64_t id = 0, rva = 0;
        if (!detail::read_u64(input, id) || !detail::read_u64(input, rva))
            return AddressError::io;
        if (i != 0 && id <= previous) return AddressError::unsorted_ids;
        previous = id;
        if (id == kLockReadId) candidate.lock_read = rva;
        if (id == kHashInsertId) candidate.hash_insert = rva;
    }
    // Detect trailing data even if the caller's size observation became stale.
    if (input.peek() != std::char_traits<char>::eof()) return AddressError::invalid_size;
    if (input.bad()) return AddressError::io;
    if (!candidate.lock_read || !candidate.hash_insert)
        return AddressError::missing_required_id;
    if (candidate.lock_read != kLockReadRva || candidate.hash_insert != kHashInsertRva)
        return AddressError::unexpected_rva;
    output = candidate;
    return AddressError::none;
}

inline bool contains_range(
    std::uint64_t image_size, std::uint64_t rva, std::size_t length) noexcept {
    return rva < image_size && length != 0 && length <= image_size - rva;
}

// The exact loop bytes in the verified 1.10.163 image. This validates identity
// only; it does not authorize editing a
// table or infer that any invocation of this routine is stuck.
inline bool matches_hash_loop(const std::uint8_t* bytes, std::size_t length) noexcept {
    if (!bytes || length != 11) return false;
    constexpr std::uint8_t prefix[]{0x44, 0x8B, 0xC9, 0x0F, 0xB7, 0x0C, 0x8A};
    for (std::size_t i = 0; i < sizeof(prefix); ++i)
        if (bytes[i] != prefix[i]) return false;
    const bool comparison = bytes[7] == 0x3B && bytes[8] == 0xCB;
    return comparison && bytes[9] == 0x75 && bytes[10] == 0xF5;
}

} // namespace freezefix
