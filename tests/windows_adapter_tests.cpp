// Compile the actual Windows adapter into this isolated test executable. No
// Fallout executable, proprietary instruction bytes, or live game are needed.
// Installation is never invoked: tests allocate their own synthetic engine
// object and exercise the production capture, commit, and pass-through paths.
#include "../src/main.cpp"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void AdapterCheck(bool passed, const char* expression, int line) {
    if (!passed) throw std::runtime_error(std::string("line ") + std::to_string(line) + ": " + expression);
}
#define REQUIRE(expression) AdapterCheck(static_cast<bool>(expression), #expression, __LINE__)

std::array<std::uint8_t, 16> g_fixture_code{};
const freezefix::CodeIdentity kFixtureIdentity{"adapter-test", 0x42, 16, {}};

void ResetAdapterState() {
    g_active.store(false);
    g_config.fix = false;
    g_config.monitor = false;
    g_log = nullptr;
    g_rebuilds.store(0);
    g_declines.store(0);
    g_dropped_events.store(0);
    g_insert_hook = {};
    g_read_hook = {};
    InitializeSListHead(&g_free_events);
    InitializeSListHead(&g_pending_events);
    for (auto& event : g_events) InterlockedPushEntrySList(&g_free_events, &event.link);

    // Installation fingerprinting is a separate gate. For direct adapter tests,
    // retain readable synthetic bytes so the real pre-commit recheck runs.
    for (std::size_t i = 0; i < g_fixture_code.size(); ++i)
        g_fixture_code[i] = static_cast<std::uint8_t>(i + 3);
    g_code_contracts.clear();
    g_code_contracts.push_back({&kFixtureIdentity,
        reinterpret_cast<std::uintptr_t>(g_fixture_code.data()),
        std::vector<std::uint8_t>(g_fixture_code.begin(), g_fixture_code.end())});
    g_contracts_ready = true;
    REQUIRE(CodeContractsUnchanged());
}

class TestRegion {
public:
    explicit TestRegion(std::size_t minimum) {
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        const std::size_t page = system.dwPageSize;
        size_ = ((minimum + page - 1) / page) * page;
        memory_ = VirtualAlloc(nullptr, size_, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        REQUIRE(memory_ != nullptr);
    }
    ~TestRegion() { if (memory_) VirtualFree(memory_, 0, MEM_RELEASE); }
    TestRegion(const TestRegion&) = delete;
    TestRegion& operator=(const TestRegion&) = delete;
    std::uintptr_t address() const { return reinterpret_cast<std::uintptr_t>(memory_); }
    std::size_t size() const { return size_; }
    void fill(unsigned char value) { std::memset(memory_, value, size_); }
    DWORD protect(DWORD protection) {
        DWORD previous = 0;
        REQUIRE(VirtualProtect(memory_, size_, protection, &previous));
        return previous;
    }
    std::vector<std::uint8_t> bytes() const {
        std::vector<std::uint8_t> result(size_);
        REQUIRE(ReadMemory(address(), result.data(), result.size()));
        return result;
    }
private:
    void* memory_ = nullptr;
    std::size_t size_ = 0;
};

template<class T> T AdapterRead(std::uintptr_t address) {
    T value{};
    REQUIRE(ReadMemory(address, &value, sizeof(value)));
    return value;
}

template<class T> void AdapterWrite(std::uintptr_t address, const T& value) {
    std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
}

struct NativeFixture {
    TestRegion object{freezefix::kArchiveObjectExtent};
    TestRegion table{8 * sizeof(archive::Entry)};
    const archive::Key* keys_reference = nullptr;
    static constexpr std::uint32_t incoming = 3;

    NativeFixture() {
        object.fill(0xA5);
        table.fill(0xCC);
        const NativeTable header{0xAABBCCDDEEFF0011ULL, table.address(), 8, 7, 5, 7};
        AdapterWrite(self(), header);
        const std::array<archive::Key, 4> keys{{{0, 1, 1}, {8, 2, 1}, {3, 3, 1}, {16, 4, 1}}};
        std::memcpy(reinterpret_cast<void*>(keys_address()), keys.data(), sizeof(keys));
        AdapterWrite(self() + freezefix::kArchiveCountOffset, incoming);
        AdapterWrite(self() + freezefix::kArchiveWriterOffset,
                     WriterLock{GetCurrentThreadId(), 0x80000001U});
        std::array<archive::Entry, 8> entries{};
        entries[0] = {0, 0};  // Corrupted cycle; all physical members remain present.
        entries[1] = {0xFFFF, 1};
        entries[3] = {0xFFFF, 2};
        std::memcpy(reinterpret_cast<void*>(table.address()), entries.data(), sizeof(entries));
        keys_reference = reinterpret_cast<const archive::Key*>(keys_address());
    }
    std::uintptr_t self() const { return object.address() + 0x10; }
    std::uintptr_t keys_address() const { return self() + freezefix::kArchiveKeysOffset; }
    NativeTable header() const { return AdapterRead<NativeTable>(self()); }
};

struct SourceBytes {
    std::vector<std::uint8_t> object;
    std::vector<std::uint8_t> table;
    const archive::Key* reference;
    explicit SourceBytes(const NativeFixture& fixture)
        : object(fixture.object.bytes()), table(fixture.table.bytes()), reference(fixture.keys_reference) {}
    void unchanged(const NativeFixture& fixture) const {
        REQUIRE(object == fixture.object.bytes());
        REQUIRE(table == fixture.table.bytes());
        REQUIRE(reference == fixture.keys_reference);
    }
};

void adapter_declines_wrong_ownership_layout_and_metadata() {
    for (unsigned fault = 0; fault < 11; ++fault) {
        ResetAdapterState();
        NativeFixture fixture;
        auto self = fixture.self();
        auto incoming = fixture.incoming;
        auto** reference = &fixture.keys_reference;
        auto header = fixture.header();
        switch (fault) {
        case 0: AdapterWrite(self + freezefix::kArchiveWriterOffset,
                            WriterLock{GetCurrentThreadId() ^ 1U, 0x80000001U}); break;
        case 1: AdapterWrite(self + freezefix::kArchiveWriterOffset,
                            WriterLock{GetCurrentThreadId(), 0x80000002U}); break;
        case 2: AdapterWrite(self + freezefix::kArchiveCountOffset, incoming + 1); break;
        case 3: fixture.keys_reference = reinterpret_cast<const archive::Key*>(fixture.keys_address() + 12); break;
        case 4: ++self; break;
        case 5: header.mask = 15; AdapterWrite(self, header); break;
        case 6: --header.available; AdapterWrite(self, header); break;
        case 7: header.entries += 2; AdapterWrite(self, header); break;
        case 8: header.entries = fixture.keys_address(); AdapterWrite(self, header); break;
        case 9: reference = nullptr; break;
        case 10: incoming = archive::kMaxNames; break;
        }
        const SourceBytes before(fixture);
        CapturedIndex captured;
        REQUIRE(!CaptureIndex(self, incoming, reference, captured));
        REQUIRE(!TryRebuild(self, incoming, reference));
        REQUIRE(g_rebuilds.load() == 0);
        before.unchanged(fixture);
    }
}

void adapter_checks_actual_windows_page_protections() {
    for (const DWORD protection : {PAGE_READONLY, PAGE_NOACCESS}) {
        ResetAdapterState();
        NativeFixture fixture;
        const SourceBytes before(fixture);
        const DWORD original = fixture.table.protect(protection);
        CapturedIndex captured;
        const bool accepted_capture = CaptureIndex(fixture.self(), fixture.incoming,
                                                    &fixture.keys_reference, captured);
        const bool accepted_repair = TryRebuild(fixture.self(), fixture.incoming, &fixture.keys_reference);
        fixture.table.protect(original);
        REQUIRE(!accepted_capture);
        REQUIRE(!accepted_repair);
        before.unchanged(fixture);
    }
    ResetAdapterState();
    NativeFixture fixture;
    const SourceBytes before(fixture);
    const DWORD original = fixture.object.protect(PAGE_READONLY);
    const bool accepted = TryRebuild(fixture.self(), fixture.incoming, &fixture.keys_reference);
    fixture.object.protect(original);
    REQUIRE(!accepted);
    before.unchanged(fixture);
}

void actual_repeated_captures_detect_changed_inputs() {
    for (unsigned field = 0; field < 4; ++field) {
        ResetAdapterState();
        NativeFixture fixture;
        CapturedIndex first;
        REQUIRE(CaptureIndex(fixture.self(), fixture.incoming, &fixture.keys_reference, first));
        CapturedIndex unchanged;
        REQUIRE(CaptureIndex(fixture.self(), fixture.incoming, &fixture.keys_reference, unchanged));
        REQUIRE(SameSnapshot(first, unchanged));
        switch (field) {
        case 0: AdapterWrite(fixture.table.address(), archive::Entry{0xFFFF, 0}); break;
        case 1: AdapterWrite(fixture.keys_address(), archive::Key{0, 99, 1}); break;
        case 2: {
            auto header = fixture.header();
            header.last_free = 6;
            AdapterWrite(fixture.self(), header);
            break;
        }
        case 3: {
            auto header = fixture.header();
            ++header.allocator;
            AdapterWrite(fixture.self(), header);
            break;
        }
        }
        CapturedIndex changed;
        REQUIRE(CaptureIndex(fixture.self(), fixture.incoming, &fixture.keys_reference, changed));
        REQUIRE(!SameSnapshot(first, changed));
    }
}

void changed_or_missing_code_evidence_blocks_the_real_commit() {
    for (unsigned fault = 0; fault < 5; ++fault) {
        ResetAdapterState();
        NativeFixture fixture;
        const SourceBytes before(fixture);
        switch (fault) {
        case 0: g_fixture_code[4] ^= 1; break;
        case 1: g_contracts_ready = false; break;
        case 2: g_code_contracts.clear(); break;
        case 3: g_config.fix = true; break;  // Missing own-hook identity must also block commit.
        case 4: g_code_contracts.front().address = 1; break;
        }
        REQUIRE(!CodeContractsUnchanged());
        REQUIRE(!TryRebuild(fixture.self(), fixture.incoming, &fixture.keys_reference));
        REQUIRE(g_rebuilds.load() == 0);
        before.unchanged(fixture);
    }
}

void successful_commit_changes_only_index_entries_and_two_metadata_fields() {
    ResetAdapterState();
    NativeFixture fixture;
    const SourceBytes before(fixture);
    CapturedIndex captured;
    REQUIRE(CaptureIndex(fixture.self(), fixture.incoming, &fixture.keys_reference, captured));
    REQUIRE(archive::Analyze(captured.view()) == archive::Validation::Rebuildable);
    REQUIRE(TryRebuild(fixture.self(), fixture.incoming, &fixture.keys_reference));
    REQUIRE(g_rebuilds.load() == 1);
    const auto after_header = fixture.header();
    REQUIRE(after_header.entries == fixture.table.address());
    REQUIRE(after_header.available == 4);
    REQUIRE(after_header.last_free < 8);
    REQUIRE(AdapterRead<std::uint32_t>(fixture.self() + freezefix::kArchiveCountOffset) == fixture.incoming);
    const auto lock = AdapterRead<WriterLock>(fixture.self() + freezefix::kArchiveWriterOffset);
    REQUIRE(lock.owner == GetCurrentThreadId());
    REQUIRE(lock.state == 0x80000001U);

    auto expected_object = before.object;
    const std::uint32_t metadata[]{after_header.available, after_header.last_free};
    std::memcpy(expected_object.data() + 0x10 + offsetof(NativeTable, available), metadata, sizeof(metadata));
    REQUIRE(expected_object == fixture.object.bytes());  // Includes all keys, count, lock, and padding.

    std::array<archive::Entry, 8> entries{};
    REQUIRE(ReadMemory(fixture.table.address(), entries.data(), sizeof(entries)));
    auto expected_table = before.table;
    std::memcpy(expected_table.data(), entries.data(), sizeof(entries));
    REQUIRE(expected_table == fixture.table.bytes());  // No writes beyond the existing allocation extent.
    std::array<unsigned, 4> membership{};
    for (const auto& entry : entries) {
        if (entry.index == 0xFFFF) continue;
        REQUIRE(entry.index < membership.size());
        ++membership[entry.index];
    }
    for (const auto count : membership) REQUIRE(count == 1);

    // Independent lookup follows the recovered engine's bucket/next behavior.
    for (std::uint32_t member = 0; member < membership.size(); ++member) {
        std::uint32_t slot = captured.keys[member].word0 & after_header.mask;
        bool found = false;
        for (std::size_t step = 0; step < entries.size(); ++step) {
            REQUIRE(slot < entries.size());
            const auto& entry = entries[slot];
            REQUIRE(entry.index < membership.size());
            const auto& key = captured.keys[entry.index];
            const auto& wanted = captured.keys[member];
            if (key.word0 == wanted.word0 && key.word1 == wanted.word1 && key.word2 == wanted.word2) {
                REQUIRE(entry.index == member);
                found = true;
                break;
            }
            if (entry.next == 0xFFFF) break;
            slot = entry.next;
        }
        REQUIRE(found);
    }
}

unsigned g_native_stub_calls = 0;
bool NativeInsertStub(void*, std::uint32_t, const archive::Key**) {
    ++g_native_stub_calls;
    return false;
}

void installed_hook_identity_checks_prefix_relay_and_destination() {
    ResetAdapterState();
    TestRegion code(128);
    const auto detour = reinterpret_cast<const void*>(&NativeInsertStub);
    const auto destination = reinterpret_cast<std::uintptr_t>(&NativeInsertStub);
    auto seed = [&](std::uint32_t entry_offset, std::uint32_t relay_offset) {
        code.fill(0xCC);
        const auto entry = code.address() + entry_offset;
        const auto relay = code.address() + relay_offset;
        const auto displacement = static_cast<std::int32_t>(relay_offset) -
                                  static_cast<std::int32_t>(entry_offset + 5);
        std::array<std::uint8_t, 5> prefix{{0xE9, 0, 0, 0, 0}};
        std::memcpy(prefix.data() + 1, &displacement, sizeof(displacement));
        std::array<std::uint8_t, 14> jump{{0xFF, 0x25}};
        std::memcpy(jump.data() + 6, &destination, sizeof(destination));
        AdapterWrite(entry, prefix);
        AdapterWrite(relay, jump);
        InstalledHook captured;
        REQUIRE(CaptureInstalledHook(reinterpret_cast<void*>(entry), detour, captured));
        REQUIRE(captured.valid);
        REQUIRE(captured.entry == entry);
        REQUIRE(captured.relay == relay);
        REQUIRE(InstalledHookUnchanged(captured));
        return captured;
    };

    const auto captured = seed(0, 32);
    InstalledHook rejected;
    AdapterWrite(captured.entry, std::uint8_t{0xEB});
    REQUIRE(!CaptureInstalledHook(reinterpret_cast<void*>(captured.entry), detour, rejected));
    REQUIRE(!InstalledHookUnchanged(captured));
    AdapterWrite(captured.entry, captured.prefix);

    AdapterWrite(captured.relay + 6, destination ^ std::uintptr_t{1});
    REQUIRE(!CaptureInstalledHook(reinterpret_cast<void*>(captured.entry), detour, rejected));
    REQUIRE(!InstalledHookUnchanged(captured));
    AdapterWrite(captured.relay, captured.relay_bytes);

    AdapterWrite(captured.relay + 1, std::uint8_t{0x24});
    REQUIRE(!CaptureInstalledHook(reinterpret_cast<void*>(captured.entry), detour, rejected));
    REQUIRE(!InstalledHookUnchanged(captured));
    AdapterWrite(captured.relay, captured.relay_bytes);
    REQUIRE(InstalledHookUnchanged(captured));

    const auto negative_displacement = seed(64, 16);
    REQUIRE(InstalledHookUnchanged(negative_displacement));
}

void hook_passes_through_when_inactive_or_called_from_another_site() {
    for (const bool active : {false, true}) {
        ResetAdapterState();
        NativeFixture fixture;
        const SourceBytes before(fixture);
        g_image_base = 0;
        g_original_insert = &NativeInsertStub;
        g_native_stub_calls = 0;
        g_active.store(active);
        REQUIRE(!HookInsert(reinterpret_cast<void*>(fixture.self()), fixture.incoming, &fixture.keys_reference));
        REQUIRE(g_native_stub_calls == 1);
        REQUIRE(g_rebuilds.load() == 0);
        REQUIRE(g_declines.load() == 0);
        before.unchanged(fixture);
    }
    g_active.store(false);
}

void bcrypt_hashes_the_standard_sha256_vector() {
    const std::vector<std::uint8_t> input{'a', 'b', 'c'};
    const std::array<std::uint8_t, 32> expected{{
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
        0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD}};
    std::array<std::uint8_t, 32> output{};
    REQUIRE(Sha256(input, output));
    REQUIRE(output == expected);
}

} // namespace

int main() {
    struct Test { const char* name; void (*run)(); };
    const Test tests[]{
        {"native ownership and layout declines", adapter_declines_wrong_ownership_layout_and_metadata},
        {"Windows page protection guards", adapter_checks_actual_windows_page_protections},
        {"repeated snapshot comparison", actual_repeated_captures_detect_changed_inputs},
        {"code revalidation prevents commit", changed_or_missing_code_evidence_blocks_the_real_commit},
        {"native commit preserves unrelated state", successful_commit_changes_only_index_entries_and_two_metadata_fields},
        {"actual hook caller gate", hook_passes_through_when_inactive_or_called_from_another_site},
        {"installed hook prefix and relay identity", installed_hook_identity_checks_prefix_relay_and_destination},
        {"Windows BCrypt SHA-256", bcrypt_hashes_the_standard_sha256_vector},
    };
    unsigned failures = 0;
    for (const auto& test : tests) {
        try {
            test.run();
            std::cout << "PASS: " << test.name << '\n';
        } catch (const std::exception& error) {
            ++failures;
            std::cerr << "FAIL: " << test.name << ": " << error.what() << '\n';
        }
    }
    if (failures) return 1;
    std::cout << "All " << (sizeof(tests) / sizeof(tests[0])) << " Windows adapter test groups passed\n";
    return 0;
}
