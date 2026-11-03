// End-to-end native integration: corrected insertion, corrected collision
// lookup, production rebuild, then insertion and lookup again.
//
// Both engine routines are caller-supplied extracts and are identity-checked
// before anything runs. Nothing here reimplements insertion or lookup.
//
// Usage: native_integration_windows <archive_insert.bin> <archive_lookup.bin>

#include "archive_index.h"
#include "native_patch.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <vector>

namespace {

constexpr std::uint32_t kParentSize = 0x1030 + 65536 * 12;
constexpr std::uint32_t kEntriesOffset = 0x18;
constexpr std::uint32_t kMaskOffset = 0x24;
constexpr std::uint32_t kAvailableOffset = 0x28;
constexpr std::uint32_t kLastFreeOffset = 0x2C;
constexpr std::uint32_t kKeysOffset = 0x1030;
constexpr std::uint32_t kCountOffset = 0x1C30;
constexpr std::uint32_t kInlineKeys = 255;
constexpr std::uint32_t kCapacity = 65536;

// archive_lookup + 0x53: lea rdx,[r9+r9*2]; lea r8,[r11+rdx*4]
constexpr std::array<std::uint8_t, 8> kLookupFirstOriginal{
    0x4B, 0x8D, 0x14, 0x49, 0x4C, 0x8D, 0x04, 0x91};

constexpr std::array<std::uint8_t, 32> kInsertSha256{
    0x48, 0x10, 0x17, 0x0D, 0x9D, 0x4C, 0xAA, 0xF6, 0xCE, 0x75, 0x09, 0x80,
    0x16, 0x8B, 0xBC, 0xF2, 0x5D, 0x30, 0xA8, 0xEB, 0x73, 0xA9, 0xC7, 0x72,
    0xF2, 0x81, 0x0D, 0x15, 0x00, 0x74, 0x79, 0xF3};
constexpr std::array<std::uint8_t, 32> kLookupSha256{
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

using InsertFn = bool (*)(void* table, std::uint32_t index, const void** keyArray, void* unused);
using LookupFn = std::uint32_t (*)(void* parent, const void* key);

struct KeyCall {
    std::uint32_t index = 0;
    std::uintptr_t address = 0;
};
KeyCall g_calls[64];
unsigned g_callCount = 0;
unsigned g_keyFailures = 0;

unsigned g_anyCall = 0;
std::uint32_t g_maxIndex = 0;

extern "C" const void* HarnessKeyAddress(const void* keyArray, std::uint32_t index) {
    ++g_anyCall;
    if (index > g_maxIndex) g_maxIndex = index;
    const auto* base = static_cast<const std::uint8_t*>(keyArray);
    if (index < kInlineKeys) {
        const auto inlineAddress = reinterpret_cast<std::uintptr_t>(
            base + index * sizeof(freezefix::archive::Key));
        g_calls[g_callCount % 64] = {index, inlineAddress};
        ++g_callCount;
        return reinterpret_cast<const void*>(inlineAddress);
    }
    std::uintptr_t vector = 0;
    std::memcpy(&vector, base + kInlineKeys * sizeof(freezefix::archive::Key), sizeof(vector));
    if (!vector) return base;
    std::array<std::uintptr_t, 3> fields{};
    std::memcpy(fields.data(), reinterpret_cast<const void*>(vector), sizeof(fields));
    const std::uintptr_t first = fields[0], last = fields[1];
    if (!first || last < first) return base;
    const std::uint32_t available =
        static_cast<std::uint32_t>((last - first) / sizeof(freezefix::archive::Key));
    const std::uint32_t wanted = index - kInlineKeys;
    if (wanted >= available) return base;
    const auto element = first + static_cast<std::uintptr_t>(wanted) * sizeof(freezefix::archive::Key);
    g_calls[g_callCount % 64] = {index, element};
    ++g_callCount;
    return reinterpret_cast<const void*>(element);
}

struct Fixture {
    std::vector<std::uint8_t> bytes = std::vector<std::uint8_t>(kParentSize, 0);
    std::vector<freezefix::archive::Entry> entries = std::vector<freezefix::archive::Entry>(kCapacity);
    std::vector<freezefix::archive::Key> keys;
    std::vector<freezefix::archive::Key> extended;
    std::array<std::uintptr_t, 3> vectorFields{};
    const void* keyArray = nullptr;

    void Build(std::vector<freezefix::archive::Key> source) {
        keys = std::move(source);
        std::memset(bytes.data(), 0, bytes.size());
        const auto entriesAddress = reinterpret_cast<std::uintptr_t>(entries.data());
        std::memcpy(bytes.data() + kEntriesOffset, &entriesAddress, sizeof(entriesAddress));
        const std::uint32_t mask = kCapacity - 1;
        std::memcpy(bytes.data() + kMaskOffset, &mask, sizeof(mask));
        const std::uint32_t available = kCapacity;
        std::memcpy(bytes.data() + kAvailableOffset, &available, sizeof(available));
        std::memcpy(bytes.data() + kLastFreeOffset, &mask, sizeof(mask));
        const std::uint32_t count = 0;
        std::memcpy(bytes.data() + kCountOffset, &count, sizeof(count));
        const std::uint32_t inlineCount = std::min<std::uint32_t>(
            static_cast<std::uint32_t>(keys.size()), kInlineKeys);
        std::memcpy(bytes.data() + kKeysOffset, keys.data(),
                    static_cast<std::size_t>(inlineCount) * sizeof(freezefix::archive::Key));
        extended.assign(keys.begin() + kInlineKeys, keys.end());
        vectorFields = {reinterpret_cast<std::uintptr_t>(extended.data()),
                        reinterpret_cast<std::uintptr_t>(extended.data() + extended.size()),
                        reinterpret_cast<std::uintptr_t>(extended.data() + extended.size())};
        const auto vectorAddress = reinterpret_cast<std::uintptr_t>(vectorFields.data());
        std::memcpy(bytes.data() + kKeysOffset + kInlineKeys * sizeof(freezefix::archive::Key),
                    &vectorAddress, sizeof(vectorAddress));
        keyArray = bytes.data() + kKeysOffset;
    }

    void* Self() { return bytes.data(); }
    void* Table() { return static_cast<std::uint8_t*>(bytes.data()) + 0x10; }
    std::uint32_t Count() const {
        std::uint32_t value = 0;
        std::memcpy(&value, bytes.data() + kCountOffset, sizeof(value));
        return value;
    }
    void SetCount(std::uint32_t value) {
        std::memcpy(bytes.data() + kCountOffset, &value, sizeof(value));
    }
    std::uint32_t Available() const {
        std::uint32_t value = 0;
        std::memcpy(&value, bytes.data() + kAvailableOffset, sizeof(value));
        return value;
    }
};

bool InsertAll(Fixture& fixture, InsertFn insert, std::uint32_t from, std::uint32_t to) {
    for (std::uint32_t index = from; index < to; ++index) {
        const void* array = fixture.keyArray;
        const bool ok = insert(fixture.Table(), index, &array, nullptr);
        if (!ok) return false;
        fixture.SetCount(index + 1);
    }
    return true;
}

bool g_trace = false;

// Daytripper's archive_lookup+0x53 detour is installed on the routine copy, so
// the first comparison reads the real key through the extended accessor. Writing
// the key into the fixed array instead would destroy the vector pointer.
unsigned LookupAll(Fixture& fixture, LookupFn lookup, std::uint32_t count) {
    unsigned missing = 0;
    for (std::uint32_t index = 0; index < count; ++index) {
        const std::uint32_t result = lookup(fixture.Self(), &fixture.keys[index]);
        if (result == index) continue;
        if (missing == 0) {
            const std::uint32_t home = fixture.keys[index].word0 & (kCapacity - 1);
            unsigned present = 0;
            for (const auto& entry : fixture.entries)
                if (entry.index == index) ++present;
            std::printf("  missing index=%u result=%u count=%u home=%u entries[home].index=%u present=%u\n",
                        index, result, count, home, fixture.entries[home].index, present);
        }
        ++missing;
    }
    return missing;
}

// Repairable damage: disconnect one chain that actually exists.
bool Damage(Fixture& fixture) {
    for (std::uint32_t slot = 0; slot < kCapacity; ++slot) {
        if (fixture.entries[slot].index != freezefix::archive::kEnd &&
            fixture.entries[slot].next != freezefix::archive::kEnd) {
            fixture.entries[slot].next = freezefix::archive::kEnd;
            return true;
        }
    }
    return false;
}

bool Rebuild(Fixture& fixture, std::uint32_t count) {
    freezefix::archive::Snapshot snapshot{fixture.entries.data(), kCapacity, fixture.keys.data(),
        count + 1, count, kCapacity - 1, fixture.Available(), kCapacity - 1};
    std::vector<freezefix::archive::Entry> staged(kCapacity);
    const auto plan = freezefix::archive::BuildRepair(snapshot, staged.data(), staged.size());
    if (plan.status != freezefix::archive::BuildStatus::Ready) {
        std::printf("  rebuild rejected status=%d validation=%d count=%u available=%u\n",
                    static_cast<int>(plan.status), static_cast<int>(plan.validation),
                    count, fixture.Available());
        return false;
    }
    const auto before = reinterpret_cast<std::uintptr_t>(fixture.entries.data());
    fixture.entries = staged;
    const auto after = reinterpret_cast<std::uintptr_t>(fixture.entries.data());
    if (before != after) std::printf("NOTE: entries buffer moved %llx -> %llx\n",
                                     static_cast<unsigned long long>(before),
                                     static_cast<unsigned long long>(after));
    // The plan's metadata must be published too, or the next insertion picks a
    // stale free slot.
    std::memcpy(fixture.bytes.data() + kAvailableOffset, &plan.available, sizeof(plan.available));
    std::memcpy(fixture.bytes.data() + kLastFreeOffset, &plan.lastFree, sizeof(plan.lastFree));
    // The rebuild publishes the incoming member too, so the active count grows
    // by one. Leaving it stale makes index count indistinguishable from
    // not-found, which is exactly what the native return value means.
    fixture.SetCount(count + 1);
    return true;
}

struct Engine {
    Executable insert, lookup;
    InsertFn insertFn = nullptr;
    LookupFn lookupFn = nullptr;
};

bool PatchWindow(Executable& target, std::uintptr_t rva, std::uintptr_t base,
                 const std::uint8_t* original, std::size_t length, void* stub) {
    auto* site = static_cast<std::uint8_t*>(target.memory) + (rva - base);
    if (std::memcmp(site, original, length) != 0) return false;
    const auto displacement = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(stub)) -
                              static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(site) + 5);
    if (displacement < INT32_MIN || displacement > INT32_MAX) return false;
    site[0] = 0xE8;
    const auto relative = static_cast<std::int32_t>(displacement);
    std::memcpy(site + 1, &relative, sizeof(relative));
    for (std::size_t i = 5; i < length; ++i) site[i] = 0x90;
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 3) {
        std::printf("usage: native_integration_windows <archive_insert.bin> <archive_lookup.bin>\n");
        return 2;
    }
    std::vector<std::uint8_t> insertCode, lookupCode;
    {
        std::ifstream file(argv[1], std::ios::binary);
        if (!file) { std::printf("FAIL open %s\n", argv[1]); return 1; }
        insertCode.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    }
    {
        std::ifstream file(argv[2], std::ios::binary);
        if (!file) { std::printf("FAIL open %s\n", argv[2]); return 1; }
        lookupCode.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    }
    std::array<std::uint8_t, 32> digest{};
    if (!Sha256(insertCode, digest) || digest != kInsertSha256) {
        std::printf("FAIL identity: archive_insert\n");
        return 1;
    }
    if (!Sha256(lookupCode, digest) || digest != kLookupSha256) {
        std::printf("FAIL identity: archive_lookup\n");
        return 1;
    }
    std::printf("PASS identity: both native routines verified\n");

    Engine engine;
    Executable stubIncoming, stubDisplaced, stubLookup;
    const auto helper = reinterpret_cast<std::uintptr_t>(&HarnessKeyAddress);
    if (!engine.insert.Load(insertCode) || !engine.lookup.Load(lookupCode) ||
        !stubIncoming.Load(freezefix::native::BuildIncomingStub(helper)) ||
        !stubDisplaced.Load(freezefix::native::BuildDisplacedStub(helper)) ||
        !stubLookup.Load(freezefix::native::BuildLookupStub(helper))) {
        std::printf("FAIL allocation\n");
        return 1;
    }
    if (!PatchWindow(engine.insert, freezefix::native::kInsertIncomingRva, 0x1B772F0,
                     freezefix::native::kInsertIncomingOriginal.data(),
                     freezefix::native::kInsertIncomingOriginal.size(), stubIncoming.memory) ||
        !PatchWindow(engine.insert, freezefix::native::kInsertDisplacedRva, 0x1B772F0,
                     freezefix::native::kInsertDisplacedOriginal.data(),
                     freezefix::native::kInsertDisplacedOriginal.size(), stubDisplaced.memory) ||
        !PatchWindow(engine.lookup, freezefix::native::kLookupLoopRva, 0x1B78AF0,
                     freezefix::native::kLookupLoopOriginal.data(),
                     freezefix::native::kLookupLoopOriginal.size(), stubLookup.memory) ||
        // Daytripper's own first-comparison detour, same stub shape.
        !PatchWindow(engine.lookup, 0x1B78B43, 0x1B78AF0,
                     kLookupFirstOriginal.data(), kLookupFirstOriginal.size(),
                     stubLookup.memory)) {
        std::printf("FAIL patch application\n");
        return 1;
    }
    FlushInstructionCache(GetCurrentProcess(), engine.insert.memory, insertCode.size());
    FlushInstructionCache(GetCurrentProcess(), engine.lookup.memory, lookupCode.size());
    {
        const auto* site25 = static_cast<const std::uint8_t*>(engine.insert.memory) + 0x25;
        const auto* siteA2 = static_cast<const std::uint8_t*>(engine.insert.memory) + 0xA2;
        std::printf("patch 0x25: %02x %02x %02x %02x %02x | 0xA2: %02x %02x %02x %02x %02x\n",
                    site25[0], site25[1], site25[2], site25[3], site25[4],
                    siteA2[0], siteA2[1], siteA2[2], siteA2[3], siteA2[4]);
    }
    engine.insertFn = reinterpret_cast<InsertFn>(engine.insert.memory);
    engine.lookupFn = reinterpret_cast<LookupFn>(engine.lookup.memory);

    // Deterministic scenarios: half uniform, half adversarial.
    std::uint32_t state = 0x1234567u;
    auto random = [&] {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    };
    unsigned scenarios = 0, failures = 0;
    for (unsigned trial = 0; trial < 1000; ++trial) {
        const std::uint32_t count = 500 + random() % 102;
        const bool adversarial = (trial % 2) == 0;
        const std::uint32_t homes = adversarial ? 1 + random() % 4 : 0;
        std::vector<freezefix::archive::Key> keys;
        keys.reserve(count + 2);
        for (std::uint32_t index = 0; index <= count + 2; ++index) {
            const std::uint32_t word0 = adversarial ? (random() % homes) * 0x1000u : random();
            keys.push_back({word0, index + 1u, trial + 1u});
        }
        Fixture fixture;
        fixture.Build(keys);
        if (!InsertAll(fixture, engine.insertFn, 0, count + 1)) {
            if (failures++ == 0) std::printf("FAIL trial %u: insertion rejected\n", trial);
            continue;
        }
        if (trial == 0) std::printf("trial 0: helper calls after insert=%u any=%u maxIndex=%u\n", g_callCount, g_anyCall, g_maxIndex);
        if (LookupAll(fixture, engine.lookupFn, count + 1) != 0) {
            if (failures++ == 0) std::printf("FAIL trial %u: lookup missed after insertion\n", trial);
            continue;
        }
        const bool damaged = Damage(fixture);
        // A uniform layout may have no collision chain at all, in which case
        // there is nothing to damage and the rebuild stage is skipped.
        if (damaged) {
            if (!Rebuild(fixture, count + 1)) {
                if (failures++ == 0) std::printf("FAIL trial %u: rebuild\n", trial);
                continue;
            }
            // The rebuild publishes the incoming member at index count+1, so the
            // post-rebuild check covers 0..count+1.
            if (LookupAll(fixture, engine.lookupFn, count + 2) != 0) {
                if (failures++ == 0) std::printf("FAIL trial %u: lookup missed after rebuild\n", trial);
                continue;
            }
        }
        if (LookupAll(fixture, engine.lookupFn, count + 1) != 0) {
            if (failures++ == 0) std::printf("FAIL trial %u: lookup missed after rebuild\n", trial);
            continue;
        }
        // The rebuild already published the incoming member at index count+1,
        // so the next insertion is count+2. This is the check that the corrected
        // insertion does not recreate the defect after a recovery.
        const unsigned callsBefore = g_callCount;
        if (failures == 0) std::printf("  post-recovery insert index=%u\n", count + 2);
        if (!InsertAll(fixture, engine.insertFn, count + 2, count + 3)) {
            if (failures++ == 0) std::printf("FAIL trial %u: post-recovery insertion\n", trial);
            continue;
        }
        const unsigned callsAfterInsert = g_callCount;

        if (LookupAll(fixture, engine.lookupFn, count + 3) != 0) {
            if (failures == 0) {
                std::vector<unsigned> seen(count + 3, 0);
                for (const auto& entry : fixture.entries)
                    if (entry.index != freezefix::archive::kEnd && entry.index < seen.size())
                        ++seen[entry.index];
                std::printf("  post-insert anomalies:");
                for (std::uint32_t i = 0; i < seen.size(); ++i)
                    if (seen[i] != 1) std::printf(" %u=%u", i, seen[i]);
                std::printf("\n  key failures=%u calls=%u->%u", g_keyFailures,
                            callsBefore, g_callCount);
                std::printf("\n  insert calls=%u tail:", callsAfterInsert - callsBefore);
                const unsigned tail = (callsAfterInsert - callsBefore) < 8
                                          ? (callsAfterInsert - callsBefore) : 8;
                for (unsigned i = callsAfterInsert - tail; i < callsAfterInsert; ++i) {
                    const auto& call = g_calls[i % 64];
                    std::printf(" %u", call.index);
                }
                std::printf("\n");
            }
            if (failures++ == 0) std::printf("FAIL trial %u: lookup missed after re-insertion\n", trial);
            continue;
        }
        ++scenarios;
    }
    std::printf("integration: scenarios=%u failures=%u\n", scenarios, failures);
    if (failures != 0) return 1;
    std::printf("PASS: insert, lookup, rebuild and re-insertion agree across %u scenarios\n", scenarios);
    return 0;
}
