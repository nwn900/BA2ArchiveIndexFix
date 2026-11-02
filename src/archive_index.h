#pragma once

// Pure model of the 1.10.163 Archive2::Index name table. This file performs no
// engine calls, pointer chasing outside caller-supplied arrays, or live writes.
// The runtime adapter must establish the exact caller, layout, owner thread,
// readable array extents, and an unchanged snapshot before committing a plan.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace freezefix {
namespace archive {

constexpr std::uint16_t kEnd = 0xFFFFu;
constexpr std::uint32_t kMaxNames = 256u;
constexpr std::uint32_t kMaxCapacity = 65536u;

struct Entry {
    std::uint16_t next = kEnd;
    std::uint16_t index = kEnd;
};
static_assert(sizeof(Entry) == 4, "native table entries are four bytes");

struct Key {
    std::uint32_t word0 = 0;
    std::uint32_t word1 = 0;
    std::uint32_t word2 = 0;
};
static_assert(sizeof(Key) == 12, "native resource IDs are twelve bytes");

struct Snapshot {
    const Entry* entries = nullptr;
    std::uint32_t capacity = 0;
    const Key* keys = nullptr;
    std::uint32_t keyCount = 0;
    std::uint32_t existingCount = 0;
    std::uint32_t mask = 0;
    std::uint32_t available = 0;
    std::uint32_t lastFree = 0;
};

enum class Validation {
    Healthy,
    Rebuildable,
    InvalidShape,
    InvalidCount,
    InvalidMetadata,
    InvalidMembership,
    DuplicateKey
};

enum class BuildStatus {
    Ready,
    NotNeeded,
    Rejected,
    OutputSizeMismatch,
    AliasedOutput,
    InsufficientCapacity,
    InternalError
};

struct BuildResult {
    BuildStatus status = BuildStatus::Rejected;
    Validation validation = Validation::InvalidShape;
    std::uint32_t available = 0;
    std::uint32_t lastFree = 0;
};

inline bool Equal(const Key& left, const Key& right) noexcept {
    return left.word0 == right.word0 && left.word1 == right.word1 &&
           left.word2 == right.word2;
}

namespace detail {

inline bool Empty(const Entry& entry) noexcept {
    return entry.next == kEnd && entry.index == kEnd;
}

inline bool MembershipMatches(const Entry* entries, std::uint32_t capacity,
                              std::uint32_t count) noexcept {
    if (count > kMaxNames) return false;
    std::array<bool, kMaxNames> seen{};
    std::uint32_t occupied = 0;
    for (std::uint32_t slot = 0; slot < capacity; ++slot) {
        const Entry entry = entries[slot];
        if (entry.index == kEnd) {
            // A partly written empty entry is not just a broken chain. Do not
            // guess whether it represents lost membership or an old repair.
            if (!Empty(entry)) return false;
            continue;
        }
        if (entry.index >= count || seen[entry.index]) return false;
        seen[entry.index] = true;
        ++occupied;
    }
    return occupied == count;
}

// Every member must be reachable from its own hash bucket. Every traversed
// entry must belong to that same bucket, and the entire chain must terminate.
// Checking the whole chain also rejects a cycle after an otherwise found key.
inline bool ValidTopology(const Entry* entries, std::uint32_t capacity,
                          const Key* keys, std::uint32_t count,
                          std::uint32_t mask) noexcept {
    for (std::uint32_t wanted = 0; wanted < count; ++wanted) {
        const std::uint32_t home = keys[wanted].word0 & mask;
        std::uint32_t current = home;
        bool found = false;
        bool ended = false;
        for (std::uint32_t step = 0; step < count; ++step) {
            if (current >= capacity) return false;
            const Entry entry = entries[current];
            if (entry.index >= count) return false;
            if ((keys[entry.index].word0 & mask) != home) return false;
            if (entry.index == wanted) found = true;
            if (entry.next == kEnd) {
                ended = true;
                break;
            }
            current = entry.next;
        }
        if (!found || !ended) return false;
    }
    return true;
}

inline bool Overlaps(const void* left, std::size_t leftBytes,
                     const void* right, std::size_t rightBytes) noexcept {
    if (!leftBytes || !rightBytes) return false;
    const auto a = reinterpret_cast<std::uintptr_t>(left);
    const auto b = reinterpret_cast<std::uintptr_t>(right);
    // Subtraction avoids an end-address overflow.
    return a <= b ? b - a < leftBytes : a - b < rightBytes;
}

inline bool NativeWouldUseSentinel(const Snapshot& snapshot) noexcept {
    const auto home = snapshot.keys[snapshot.existingCount].word0 & snapshot.mask;
    if (Empty(snapshot.entries[home]) || snapshot.available == 0) return false;
    std::uint32_t cursor = snapshot.lastFree;
    for (std::uint32_t step = 0; step < snapshot.capacity; ++step) {
        cursor = (cursor - 1u) & snapshot.mask;
        if (Empty(snapshot.entries[cursor])) return cursor == kEnd;
    }
    return false;  // The membership/free-count checks make this unreachable.
}

// Insert one member into an initially valid private table, following the
// engine's collision/relocation rules. Slot 0xFFFF may be a direct hash home,
// but can never be an overflow link: its link encoding means end-of-chain.
inline bool Insert(Entry* entries, std::uint32_t capacity, const Key* keys,
                   std::uint32_t index, std::uint32_t mask,
                   std::uint32_t& available, std::uint32_t& cursor) noexcept {
    const std::uint32_t home = keys[index].word0 & mask;
    if (Empty(entries[home])) {
        entries[home] = Entry{kEnd, static_cast<std::uint16_t>(index)};
        --available;
        return true;
    }
    if (available == 0) return false;

    std::uint32_t freeSlot = capacity;
    for (std::uint32_t step = 0; step < capacity; ++step) {
        cursor = (cursor - 1u) & mask;
        if (cursor != kEnd && Empty(entries[cursor])) {
            freeSlot = cursor;
            break;
        }
    }
    if (freeSlot == capacity) return false;

    const Entry displaced = entries[home];
    if (displaced.index >= index) return false;
    const std::uint32_t originalHome = keys[displaced.index].word0 & mask;
    if (originalHome == home) {
        entries[freeSlot] = Entry{displaced.next, static_cast<std::uint16_t>(index)};
        entries[home].next = static_cast<std::uint16_t>(freeSlot);
    } else {
        std::uint32_t previous = originalHome;
        bool found = false;
        for (std::uint32_t step = 0; step < index; ++step) {
            if (previous >= capacity || entries[previous].index >= index) return false;
            if (entries[previous].next == home) {
                found = true;
                break;
            }
            if (entries[previous].next == kEnd) return false;
            previous = entries[previous].next;
        }
        if (!found) return false;
        entries[freeSlot] = displaced;
        entries[previous].next = static_cast<std::uint16_t>(freeSlot);
        entries[home] = Entry{kEnd, static_cast<std::uint16_t>(index)};
    }
    --available;
    return true;
}

}  // namespace detail

inline Validation Analyze(const Snapshot& snapshot) noexcept {
    const std::uint32_t capacity = snapshot.capacity;
    if (!snapshot.entries || !snapshot.keys || capacity < 2u ||
        capacity > kMaxCapacity || (capacity & (capacity - 1u)) != 0) {
        return Validation::InvalidShape;
    }
    if (snapshot.existingCount >= kMaxNames ||
        snapshot.keyCount != snapshot.existingCount + 1u ||
        snapshot.existingCount > capacity) {
        return Validation::InvalidCount;
    }
    if (snapshot.mask != capacity - 1u || snapshot.lastFree >= capacity ||
        snapshot.available != capacity - snapshot.existingCount) {
        return Validation::InvalidMetadata;
    }
    if (!detail::MembershipMatches(snapshot.entries, capacity, snapshot.existingCount)) {
        return Validation::InvalidMembership;
    }
    for (std::uint32_t i = 0; i < snapshot.keyCount; ++i) {
        for (std::uint32_t j = 0; j < i; ++j) {
            if (Equal(snapshot.keys[i], snapshot.keys[j])) return Validation::DuplicateKey;
        }
    }
    if (!detail::ValidTopology(snapshot.entries, capacity, snapshot.keys,
                               snapshot.existingCount, snapshot.mask) ||
        detail::NativeWouldUseSentinel(snapshot)) {
        return Validation::Rebuildable;
    }
    return Validation::Healthy;
}

// On Ready, output contains all existing members AND the incoming member at
// external index existingCount. The caller must return success instead of
// inserting that member again. Healthy/invalid snapshots leave output alone.
// A failed staging operation must never be committed. Source entries and keys
// are never modified, even on rejection; output is required to be disjoint.
inline BuildResult BuildRepair(const Snapshot& snapshot, Entry* output,
                               std::size_t outputCount) noexcept {
    BuildResult result{};
    result.validation = Analyze(snapshot);
    if (result.validation == Validation::Healthy) {
        result.status = BuildStatus::NotNeeded;
        return result;
    }
    if (result.validation != Validation::Rebuildable) return result;
    if (!output || outputCount != snapshot.capacity) {
        result.status = BuildStatus::OutputSizeMismatch;
        return result;
    }
    if (detail::Overlaps(output, outputCount * sizeof(Entry), snapshot.entries,
                         static_cast<std::size_t>(snapshot.capacity) * sizeof(Entry)) ||
        detail::Overlaps(output, outputCount * sizeof(Entry), snapshot.keys,
                         static_cast<std::size_t>(snapshot.keyCount) * sizeof(Key))) {
        result.status = BuildStatus::AliasedOutput;
        return result;
    }
    if (snapshot.existingCount + 1u > snapshot.capacity) {
        result.status = BuildStatus::InsufficientCapacity;
        return result;
    }

    std::fill_n(output, outputCount, Entry{});
    std::uint32_t available = snapshot.capacity;
    std::uint32_t cursor = snapshot.mask;
    for (std::uint32_t index = 0; index < snapshot.keyCount; ++index) {
        if (!detail::Insert(output, snapshot.capacity, snapshot.keys, index,
                            snapshot.mask, available, cursor)) {
            result.status = BuildStatus::InternalError;
            return result;
        }
    }
    if (available != snapshot.capacity - snapshot.keyCount ||
        !detail::MembershipMatches(output, snapshot.capacity, snapshot.keyCount) ||
        !detail::ValidTopology(output, snapshot.capacity, snapshot.keys,
                               snapshot.keyCount, snapshot.mask)) {
        result.status = BuildStatus::InternalError;
        return result;
    }
    result.status = BuildStatus::Ready;
    result.available = available;
    result.lastFree = cursor;
    return result;
}

}  // namespace archive
}  // namespace freezefix
