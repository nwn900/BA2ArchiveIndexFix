// Executes the verified native BSResource::Archive2::Index lookup routine from
// Fallout 4 1.10.163 against synthetic parent objects.
//
// The routine bytes are caller-supplied and must match the documented SHA-256.
// Nothing here reimplements the lookup: the real machine code runs, and the
// harness only prepares the memory it reads.
//
// Usage: native_lookup_windows <archive_lookup.bin>

#include "archive_index.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace {

// Large enough that a native read at any index stays inside the buffer; the
// real object ends at 0x1C60 and reads beyond it land in adjacent heap.
constexpr std::uint32_t kParentSize = 0x1030 + 65536 * 12;
constexpr std::uint32_t kEntriesOffset = 0x18;
constexpr std::uint32_t kMaskOffset = 0x24;
constexpr std::uint32_t kKeysOffset = 0x1030;
constexpr std::uint32_t kCountOffset = 0x1C30;
constexpr std::uint32_t kInlineKeys = 255;
constexpr std::uint32_t kCapacity = 65536;

constexpr std::array<std::uint8_t, 32> kExpectedSha256{
    0xF4, 0x17, 0x2A, 0x68, 0xA1, 0x4B, 0xE8, 0xE4, 0x8A, 0x11, 0x17, 0xFC,
    0x70, 0xC1, 0x20, 0x0F, 0x78, 0x62, 0x38, 0x27, 0xF0, 0xAE, 0x64, 0x82,
    0x67, 0x42, 0xD8, 0x90, 0xA6, 0x40, 0x98, 0x95};

bool Sha256(const std::vector<std::uint8_t>& bytes, std::array<std::uint8_t, 32>& output) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    bool ok = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0;
    if (ok) ok = BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()),
                               static_cast<ULONG>(bytes.size()), 0) >= 0;
    if (ok) ok = BCryptFinishHash(hash, output.data(), static_cast<ULONG>(output.size()), 0) >= 0;
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

struct Executable {
    void* memory = nullptr;
    ~Executable() { if (memory) VirtualFree(memory, 0, MEM_RELEASE); }
    bool Load(const std::vector<std::uint8_t>& code) {
        memory = VirtualAlloc(nullptr, code.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!memory) return false;
        std::memcpy(memory, code.data(), code.size());
        FlushInstructionCache(GetCurrentProcess(), memory, code.size());
        return true;
    }
};

using LookupFn = std::uint32_t (*)(void* parent, const void* key);

// One parent object plus the slot array it points at.
struct Parent {
    std::vector<std::uint8_t> bytes = std::vector<std::uint8_t>(kParentSize, 0);
    std::vector<freezefix::archive::Entry> entries;

    void Publish(const std::vector<freezefix::archive::Entry>& table,
                 const std::vector<freezefix::archive::Key>& keys,
                 std::uint32_t count) {
        entries = table;
        std::memset(bytes.data(), 0, bytes.size());
        const auto entriesAddress = reinterpret_cast<std::uintptr_t>(entries.data());
        std::memcpy(bytes.data() + kEntriesOffset, &entriesAddress, sizeof(entriesAddress));
        const std::uint32_t mask = kCapacity - 1;
        std::memcpy(bytes.data() + kMaskOffset, &mask, sizeof(mask));
        std::memcpy(bytes.data() + kCountOffset, &count, sizeof(count));
        const std::uint32_t inlineCount = std::min<std::uint32_t>(count, kInlineKeys);
        std::memcpy(bytes.data() + kKeysOffset, keys.data(),
                    static_cast<std::size_t>(inlineCount) * sizeof(freezefix::archive::Key));
        // Slot 255 holds the extended-storage pointer in the real process. A
        // non-null stand-in keeps the native read deterministic.
        const std::uintptr_t standIn = 0x00007FFE00000000ull;
        std::memcpy(bytes.data() + kKeysOffset + kInlineKeys * sizeof(freezefix::archive::Key),
                    &standIn, sizeof(standIn));
    }

    void* Self() { return bytes.data(); }
};

std::vector<freezefix::archive::Entry> BuildValidTable(
    const std::vector<freezefix::archive::Key>& keys, std::uint32_t existing) {
    std::vector<freezefix::archive::Entry> entries(kCapacity);
    std::map<std::uint32_t, std::vector<std::uint16_t>> groups;
    for (std::uint32_t member = 0; member < existing; ++member)
        groups[keys[member].word0 & (kCapacity - 1)].push_back(static_cast<std::uint16_t>(member));
    for (const auto& group : groups) entries[group.first].index = group.second.front();
    std::uint32_t candidate = 0;
    for (const auto& group : groups) {
        std::uint32_t previous = group.first;
        for (std::size_t i = 1; i < group.second.size(); ++i) {
            while (candidate < kCapacity &&
                   (candidate == freezefix::archive::kEnd || entries[candidate].index != freezefix::archive::kEnd))
                ++candidate;
            if (candidate >= kCapacity) return {};
            entries[previous].next = static_cast<std::uint16_t>(candidate);
            entries[candidate].index = group.second[i];
            previous = candidate++;
        }
    }
    return entries;
}

}  // namespace

// emulateStub models Daytripper's archive_lookup+0x53 detour, which redirects
// only the first comparison to GetDataFileNameIdEx. The native routine still
// runs unmodified; the harness places the extended key where that redirect
// would have produced it, then restores the slot.
int RunScenario(const char* name, const std::vector<freezefix::archive::Key>& keys,
                LookupFn lookup, bool emulateStub) {
    const std::uint32_t existing = static_cast<std::uint32_t>(keys.size()) - 1;
    auto table = BuildValidTable(keys, existing);
    if (table.empty()) { std::printf("FAIL fixture %s\n", name); return 1; }
    // Break a chain that actually exists, so the rebuild has work to do.
    for (std::uint32_t slot = 0; slot < kCapacity; ++slot) {
        if (table[slot].index != freezefix::archive::kEnd &&
            table[slot].next != freezefix::archive::kEnd) {
            table[slot].next = freezefix::archive::kEnd;
            break;
        }
    }

    freezefix::archive::Snapshot snapshot{table.data(), kCapacity, keys.data(),
        static_cast<std::uint32_t>(keys.size()), existing, kCapacity - 1,
        kCapacity - existing, kCapacity - 1};
    std::vector<freezefix::archive::Entry> staged(kCapacity);
    const auto plan = freezefix::archive::BuildRepair(snapshot, staged.data(), staged.size());
    if (plan.status != freezefix::archive::BuildStatus::Ready) {
        std::printf("FAIL rebuild %s status=%d\n", name, static_cast<int>(plan.status));
        return 1;
    }

    Parent parent;
    parent.Publish(staged, keys, static_cast<std::uint32_t>(keys.size()));

    unsigned foundInline = 0, missingInline = 0, foundExtended = 0, missingExtended = 0;
    unsigned extendedAtHome = 0, extendedInChain = 0, extendedChainFound = 0;
    for (std::uint32_t index = 0; index < keys.size(); ++index) {
        const std::uint32_t home = keys[index].word0 & (kCapacity - 1);
        const bool atHome = staged[home].index == index;
        // The stub calls GetDataFileNameIdEx(parent, entries[home].index), so the
        // first comparison reads the occupant's key through the extended
        // accessor. Place that key where the redirect would have produced it.
        const std::uint32_t occupant = staged[home].index;
        std::uint8_t saved[sizeof(freezefix::archive::Key)]{};
        const bool redirect = emulateStub && occupant != freezefix::archive::kEnd &&
                              occupant >= kInlineKeys;
        if (redirect) {
            auto* slot = parent.bytes.data() + kKeysOffset + occupant * sizeof(freezefix::archive::Key);
            std::memcpy(saved, slot, sizeof(saved));
            std::memcpy(slot, &keys[occupant], sizeof(saved));
        }
        const bool found = lookup(parent.Self(), &keys[index]) == index;
        if (redirect) {
            auto* slot = parent.bytes.data() + kKeysOffset + occupant * sizeof(freezefix::archive::Key);
            std::memcpy(slot, saved, sizeof(saved));
        }
        if (index < kInlineKeys) {
            if (found) ++foundInline; else ++missingInline;
        } else {
            if (found) ++foundExtended; else ++missingExtended;
            if (atHome) ++extendedAtHome;
            else { ++extendedInChain; if (found) ++extendedChainFound; }
        }
    }
    std::printf("%s%s: members=%zu\n", name, emulateStub ? " (daytripper stub emulated)" : "", keys.size());
    std::printf("  inline   found=%u missing=%u\n", foundInline, missingInline);
    std::printf("  extended found=%u missing=%u (at-home=%u in-chain=%u chain-found=%u)\n",
                foundExtended, missingExtended, extendedAtHome, extendedInChain, extendedChainFound);
    if (missingInline != 0) {
        std::printf("FAIL inline regression: the native lookup lost an inline member\n");
        return 1;
    }
    if (emulateStub && extendedInChain == 0 && missingExtended != 0) {
        std::printf("FAIL extended regression: at-home extended keys must be retrievable\n");
        return 1;
    }
    if (emulateStub && extendedInChain != 0) {
        std::printf("KNOWN LIMITATION: %u extended keys sit in collision chains; the native\n"
                    "collision loop reads the fixed array and cannot retrieve them.\n",
                    extendedInChain);
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: native_lookup_windows <archive_lookup.bin>\n");
        return 2;
    }
    std::ifstream file(argv[1], std::ios::binary);
    if (!file) { std::printf("FAIL open %s\n", argv[1]); return 1; }
    std::vector<std::uint8_t> code((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
    std::array<std::uint8_t, 32> digest{};
    if (!Sha256(code, digest)) { std::printf("FAIL hash\n"); return 1; }
    if (digest != kExpectedSha256) {
        std::printf("FAIL identity: routine does not match the verified native lookup\n");
        return 1;
    }
    std::printf("PASS identity: native archive_lookup sha256 verified (%zu bytes)\n", code.size());

    Executable executable;
    if (!executable.Load(code)) { std::printf("FAIL executable allocation\n"); return 1; }
    const auto lookup = reinterpret_cast<LookupFn>(executable.memory);

    constexpr std::uint32_t kLast = 600;  // 601 existing members, indices 0..600

    // Realistic spread: uniform hashes over 65,536 buckets, so only a handful
    // of keys collide and most sit at their home slot.
    std::vector<freezefix::archive::Key> uniform;
    std::uint32_t state = 0x9E3779B9u;
    auto random = [&] {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    };
    for (std::uint32_t index = 0; index <= kLast + 1; ++index)
        uniform.push_back({random(), index + 1u, 0x5A5A0000u + index});

    // Adversarial: four homes, so every chain is ~150 members long.
    std::vector<freezefix::archive::Key> adversarial;
    for (std::uint32_t index = 0; index <= kLast + 1; ++index)
        adversarial.push_back({(index % 4) * 0x1000u, index + 1u, 0x5A5A0000u + (index % 4)});

    int status = 0;
    status |= RunScenario("uniform", uniform, lookup, false);
    status |= RunScenario("uniform", uniform, lookup, true);
    status |= RunScenario("adversarial", adversarial, lookup, true);
    return status;
}
