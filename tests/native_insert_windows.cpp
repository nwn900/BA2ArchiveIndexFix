// Executes the verified native archive_insert routine from Fallout 4 1.10.163
// against a Daytripper-compatible parent object, with and without the key-access
// correction FreezeFixF4 installs.
//
// Usage: native_insert_windows <archive_insert.bin>

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
// The routine takes the table pointer (parent + 0x10), so these are
// parent-relative: table+0x18 and table+0x1C.
constexpr std::uint32_t kAvailableOffset = 0x28;
constexpr std::uint32_t kLastFreeOffset = 0x2C;
constexpr std::uint32_t kKeysOffset = 0x1030;
constexpr std::uint32_t kCountOffset = 0x1C30;
constexpr std::uint32_t kInlineKeys = 255;
constexpr std::uint32_t kCapacity = 65536;

constexpr std::array<std::uint8_t, 32> kExpectedSha256{
    0x48, 0x10, 0x17, 0x0D, 0x9D, 0x4C, 0xAA, 0xF6, 0xCE, 0x75, 0x09, 0x80,
    0x16, 0x8B, 0xBC, 0xF2, 0x5D, 0x30, 0xA8, 0xEB, 0x73, 0xA9, 0xC7, 0x72,
    0xF2, 0x81, 0x0D, 0x15, 0x00, 0x74, 0x79, 0xF3};

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

using InsertFn = bool (*)(void* parent, std::uint32_t index, const void** keyArray, void* unused);

unsigned g_calls = 0;

extern "C" const void* HarnessKeyAddress(const void* keyArray, std::uint32_t index) {
    std::printf("  keyaddr index=%u\n", index);
    ++g_calls;
    const auto* base = static_cast<const std::uint8_t*>(keyArray);
    if (index < kInlineKeys) return base + index * sizeof(freezefix::archive::Key);
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
    return reinterpret_cast<const void*>(first + wanted * sizeof(freezefix::archive::Key));
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
        const std::uint32_t lastFree = mask;
        std::memcpy(bytes.data() + kLastFreeOffset, &lastFree, sizeof(lastFree));
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
    std::uint32_t Count() const {
        std::uint32_t value = 0;
        std::memcpy(&value, bytes.data() + kCountOffset, sizeof(value));
        return value;
    }
    void SetCount(std::uint32_t value) {
        std::memcpy(bytes.data() + kCountOffset, &value, sizeof(value));
    }
};

// Every inserted member must be reachable from its own bucket exactly once.
bool Verify(const Fixture& fixture, std::uint32_t inserted) {
    std::vector<unsigned> seen(inserted, 0);
    for (const auto& entry : fixture.entries) {
        if (entry.index == freezefix::archive::kEnd) continue;
        if (entry.index >= inserted) return false;
        ++seen[entry.index];
    }
    for (std::uint32_t member = 0; member < inserted; ++member)
        if (seen[member] != 1) return false;
    for (std::uint32_t member = 0; member < inserted; ++member) {
        const std::uint32_t home = fixture.keys[member].word0 & (kCapacity - 1);
        std::uint32_t position = home;
        bool found = false;
        for (std::uint32_t steps = 0; steps < inserted + 1; ++steps) {
            if (position >= kCapacity) return false;
            const auto& entry = fixture.entries[position];
            if (entry.index >= inserted) return false;
            if (entry.index == member) { found = true; break; }
            if (entry.next == freezefix::archive::kEnd) break;
            position = entry.next;
        }
        if (!found) return false;
    }
    return true;
}

unsigned RunScenario(const char* name, const std::vector<freezefix::archive::Key>& keys,
                     InsertFn insert, bool corrected) {
    Fixture fixture;
    fixture.Build(keys);
    unsigned failures = 0;
    for (std::uint32_t index = 0; index < keys.size(); ++index) {
        const void* array = fixture.keyArray;
        if (!insert(static_cast<std::uint8_t*>(fixture.Self()) + 0x10, index, &array, nullptr)) {
            std::printf("%s: insert %u returned false\n", name, index);
            return failures + 1;
        }
        fixture.SetCount(index + 1);
        if (!Verify(fixture, index + 1)) {
            if (failures == 0) std::printf("FAIL %s: table invalid after insert %u\n", name, index);
            ++failures;
            if (failures > 3) break;
        }
    }
    std::printf("%s%s: inserted=%zu failures=%u\n", name, corrected ? " (corrected)" : "",
                keys.size(), failures);
    return failures;
}

}  // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 2) { std::printf("usage: native_insert_windows <archive_insert.bin>\n"); return 2; }
    std::ifstream file(argv[1], std::ios::binary);
    if (!file) { std::printf("FAIL open %s\n", argv[1]); return 1; }
    std::vector<std::uint8_t> code((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
    std::array<std::uint8_t, 32> digest{};
    if (!Sha256(code, digest)) { std::printf("FAIL hash\n"); return 1; }
    if (digest != kExpectedSha256) {
        std::printf("FAIL identity: routine does not match the verified native insert\n");
        return 1;
    }
    std::printf("PASS identity: native archive_insert sha256 verified (%zu bytes)\n", code.size());

    constexpr std::uint32_t kLast = 600;
    std::vector<freezefix::archive::Key> keys;
    for (std::uint32_t index = 0; index <= kLast; ++index)
        keys.push_back({(index % 4) * 0x1000u, index + 1u, 0x5A5A0000u + (index % 4)});

    // Uniform hashes: most keys land on their own home, so the displaced path
    // runs rarely and with unrelated buckets.
    std::vector<freezefix::archive::Key> uniform;
    std::uint32_t state = 0x1234567u;
    auto random = [&] {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    };
    for (std::uint32_t index = 0; index <= kLast; ++index)
        uniform.push_back({random(), index + 1u, 0x5A5A0000u + index});

    unsigned baseline = 0;
    {
        Executable executable;
        if (!executable.Load(code)) { std::printf("FAIL allocation\n"); return 1; }
        baseline = RunScenario("adversarial", keys, reinterpret_cast<InsertFn>(executable.memory), false);
        RunScenario("uniform", uniform, reinterpret_cast<InsertFn>(executable.memory), false);
    }

    std::vector<std::uint8_t> patched = code;
    Executable stubIncoming, stubDisplaced, corrected;
    const auto helper = reinterpret_cast<std::uintptr_t>(&HarnessKeyAddress);
    if (!stubIncoming.Load(freezefix::native::BuildIncomingStub(helper)) ||
        !stubDisplaced.Load(freezefix::native::BuildDisplacedStub(helper)) ||
        !corrected.Load(patched)) {
        std::printf("FAIL stub allocation\n");
        return 1;
    }
    auto patch = [&](std::uintptr_t rva, const std::uint8_t* original, std::size_t length,
                     void* stub) {
        const auto offset = static_cast<std::size_t>(rva - 0x1B772F0);
        auto* site = static_cast<std::uint8_t*>(corrected.memory) + offset;
        if (std::memcmp(site, original, length) != 0) return false;
        const auto displacement = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(stub)) -
                                  static_cast<std::int64_t>(
                                      reinterpret_cast<std::uintptr_t>(site) + 5);
        if (displacement < INT32_MIN || displacement > INT32_MAX) return false;
        site[0] = 0xE8;
        const auto relative = static_cast<std::int32_t>(displacement);
        std::memcpy(site + 1, &relative, sizeof(relative));
        for (std::size_t i = 5; i < length; ++i) site[i] = 0x90;
        return true;
    };
    if (!patch(freezefix::native::kInsertIncomingRva,
               freezefix::native::kInsertIncomingOriginal.data(),
               freezefix::native::kInsertIncomingOriginal.size(), stubIncoming.memory) ||
        !patch(freezefix::native::kInsertDisplacedRva,
               freezefix::native::kInsertDisplacedOriginal.data(),
               freezefix::native::kInsertDisplacedOriginal.size(), stubDisplaced.memory)) {
        std::printf("FAIL patch application\n");
        return 1;
    }
    {
        const auto* bytes = static_cast<const std::uint8_t*>(stubDisplaced.memory);
        std::printf("displaced stub:");
        for (unsigned i = 0; i < 57; ++i) std::printf(" %02x", bytes[i]);
        std::printf("\n");
    }
    FlushInstructionCache(GetCurrentProcess(), corrected.memory, patched.size());
    const unsigned fixed = RunScenario("adversarial", keys,
                                       reinterpret_cast<InsertFn>(corrected.memory), true);
    const unsigned fixedUniform = RunScenario("uniform", uniform,
                                              reinterpret_cast<InsertFn>(corrected.memory), true);
    if (fixedUniform != 0) {
        std::printf("FAIL: uniform distribution lost members after correction\n");
        return 1;
    }
    if (baseline == 0) {
        std::printf("FAIL: the unpatched routine was expected to corrupt the table\n");
        return 1;
    }
    if (fixed != 0) {
        std::printf("FAIL: the correction did not restore every insertion\n");
        return 1;
    }
    std::printf("PASS: unpatched corrupts at the first extended index; corrected inserts all %zu keys\n",
                keys.size());
    return 0;
}
