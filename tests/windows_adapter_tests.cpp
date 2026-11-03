// Compile the actual Windows adapter into this isolated test executable. No
// Fallout executable, proprietary instruction bytes, or live game are needed.
// Installation is never invoked: tests allocate their own synthetic engine
// object and exercise the production capture, commit, and pass-through paths.
#include "../src/main.cpp"
#include "detour_fixtures.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

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
    g_extended_declines.store(0);
    g_suppressed_extended_events.store(0);
    g_highest_extended_incoming.store(0);
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
    g_extended_archive_storage = false;
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

std::vector<Event> CollectQueuedEvents() {
    std::vector<Event> result;
    PSLIST_ENTRY entry = InterlockedFlushSList(&g_pending_events);
    while (entry) {
        auto* node = reinterpret_cast<EventNode*>(entry);
        entry = entry->Next;
        result.push_back(node->event);
        InterlockedPushEntrySList(&g_free_events, &node->link);
    }
    return result;
}

std::string EventText(const Event& event) {
    char text[768]{};
    REQUIRE(FormatEvent(event, text, sizeof(text)));
    return text;
}

void unsupported_storage_diagnostics_read_only_the_exact_raw_header() {
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    const std::size_t page = system.dwPageSize;
    for (unsigned mode = 0; mode < 4; ++mode) {
        ResetAdapterState();
        g_extended_archive_storage = true;
        TestRegion region(page * 2);
        region.fill(0xA5);
        // Only the raw header is provided. Its entries pointer is deliberately
        // unreadable, as is keys_reference. No lock/object/vector is present.
        const std::array<std::uint32_t, 8> words{{0x55667788U, 0x11223344U, 1, 0,
            mode == 1 ? 0U : 2048U, 0x7FFU, 0x6E2U, 0x7FFU}};
        const auto self = region.address() + page - (mode == 3 ? 16 : 32);
        AdapterWrite(self, words);
        const auto before = region.bytes();
        DWORD first_protection = 0, second_protection = 0;
        REQUIRE(VirtualProtect(reinterpret_cast<void*>(region.address() + page), page,
                               PAGE_NOACCESS, &second_protection));
        REQUIRE(VirtualProtect(reinterpret_cast<void*>(region.address()), page,
                               mode == 2 ? PAGE_NOACCESS : PAGE_READONLY, &first_protection));
        const bool rebuilt = TryRebuild(self, 286,
            reinterpret_cast<const archive::Key**>(std::uintptr_t{1}));
        DWORD ignored = 0;
        REQUIRE(VirtualProtect(reinterpret_cast<void*>(region.address()), page, first_protection, &ignored));
        REQUIRE(VirtualProtect(reinterpret_cast<void*>(region.address() + page), page,
                               second_protection, &ignored));
        REQUIRE(!rebuilt);
        REQUIRE(region.bytes() == before);
        REQUIRE(g_rebuilds.load() == 0);
        REQUIRE(g_declines.load() == 1);
        REQUIRE(g_extended_declines.load() == 1);
        REQUIRE(g_highest_extended_incoming.load() == 286);
        REQUIRE(g_suppressed_extended_events.load() == 0);
        REQUIRE(g_dropped_events.load() == 0);
        const auto events = CollectQueuedEvents();
        REQUIRE(events.size() == 1);
        const auto& event = events.front();
        REQUIRE(std::strcmp(event.kind, "DECLINED") == 0);
        REQUIRE(std::strcmp(event.reason,
            "extended-archive-keys-unreadable-or-layout-mismatch") == 0);
        REQUIRE(event.table == self && event.index == 286);
        REQUIRE(event.header_requested);
        REQUIRE(event.reason_occurrence == 1);
        const auto line = EventText(event);
        REQUIRE(line.find("reason_occurrence=1 reporting=powers-of-two") != std::string::npos);
        if (mode < 2) {
            // A read ending exactly at the inaccessible page succeeds. A zero
            // actually read at +0x10 is distinct from missing evidence.
            REQUIRE(event.header.readable);
            REQUIRE(event.header.words == words);
            REQUIRE(event.capacity == words[4]);
            REQUIRE(event.capacity_source == CapacitySource::RawHeader);
            REQUIRE(line.find(mode == 1 ? "capacity=0 " : "capacity=2048 ") != std::string::npos);
            REQUIRE(line.find("capacity_source=raw-header+0x10-unvalidated") != std::string::npos);
            REQUIRE(line.find("raw_header_u32_00_1C=[55667788,11223344,00000001,00000000,") !=
                    std::string::npos);
            REQUIRE(line.find(mode == 1 ? ",00000000,000007FF,000006E2,000007FF]" :
                                         ",00000800,000007FF,000006E2,000007FF]") != std::string::npos);
        } else {
            // Neither a wholly unreadable header nor a partial 16-byte read is
            // reported as a real zero capacity or as a complete byte snapshot.
            REQUIRE(!event.header.readable);
            REQUIRE(event.header.words == (std::array<std::uint32_t, 8>{}));
            REQUIRE(event.capacity_source == CapacitySource::Unavailable);
            REQUIRE(line.find("capacity=unavailable ") != std::string::npos);
            REQUIRE(line.find("raw_header=unavailable") != std::string::npos);
            REQUIRE(line.find("capacity=0 ") == std::string::npos);
        }
    }
}

void repeated_unsupported_declines_preserve_counters_and_event_capacity() {
    ResetAdapterState();
    g_extended_archive_storage = true;
    TestRegion header(sizeof(NativeTable));
    const NativeTable raw{0x1122334455667788ULL, 1, 2048, 2047, 1762, 2047};
    AdapterWrite(header.address(), raw);
    const auto before = header.bytes();
    constexpr std::uint32_t first = 286, attempts = 1537;
    for (std::uint32_t index = 0; index < attempts; ++index)
        REQUIRE(!TryRebuild(header.address(), first + index,
            reinterpret_cast<const archive::Key**>(std::uintptr_t{1})));
    REQUIRE(header.bytes() == before);
    REQUIRE(g_rebuilds.load() == 0);
    REQUIRE(g_declines.load() == attempts);
    REQUIRE(g_extended_declines.load() == attempts);
    REQUIRE(g_highest_extended_incoming.load() == first + attempts - 1);
    REQUIRE(g_suppressed_extended_events.load() == attempts - 11);
    REQUIRE(g_dropped_events.load() == 0);

    // Keep all sampled events queued while a real supported recovery occurs;
    // the unsupported insertion flood must leave space for its REBUILT event.
    NativeFixture supported;
    REQUIRE(TryRebuild(supported.self(), supported.incoming, &supported.keys_reference));
    REQUIRE(g_rebuilds.load() == 1);
    REQUIRE(g_declines.load() == attempts);
    auto events = CollectQueuedEvents();
    REQUIRE(events.size() == 12);
    std::vector<std::uint64_t> occurrences;
    unsigned rebuild_events = 0;
    for (const auto& event : events) {
        if (std::strcmp(event.kind, "REBUILT") == 0) {
            ++rebuild_events;
            REQUIRE(event.capacity_source == CapacitySource::ValidatedSnapshot);
            continue;
        }
        REQUIRE(event.capacity_source == CapacitySource::RawHeader);
        REQUIRE(event.capacity == 2048);
        REQUIRE(event.index == first + event.reason_occurrence - 1);
        occurrences.push_back(event.reason_occurrence);
    }
    std::sort(occurrences.begin(), occurrences.end());
    std::vector<std::uint64_t> expected;
    for (std::uint64_t occurrence = 1; occurrence <= attempts; occurrence *= 2)
        expected.push_back(occurrence);
    REQUIRE(occurrences == expected);
    REQUIRE(rebuild_events == 1);

    // Concurrent callers still contribute exactly once to each total and to
    // the maximum, even though sampled event publication order can differ.
    ResetAdapterState();
    g_extended_archive_storage = true;
    std::atomic<bool> unexpected_rebuild{false};
    std::vector<std::thread> threads;
    constexpr std::uint32_t workers = 4, per_worker = 400;
    for (std::uint32_t worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&, worker] {
            for (std::uint32_t index = 0; index < per_worker; ++index)
                if (TryRebuild(header.address(), first + worker * per_worker + index,
                    reinterpret_cast<const archive::Key**>(std::uintptr_t{1})))
                    unexpected_rebuild.store(true);
        });
    }
    for (auto& thread : threads) thread.join();
    REQUIRE(!unexpected_rebuild.load());
    REQUIRE(g_declines.load() == workers * per_worker);
    REQUIRE(g_extended_declines.load() == workers * per_worker);
    REQUIRE(g_suppressed_extended_events.load() == workers * per_worker - 11);
    REQUIRE(g_highest_extended_incoming.load() == first + workers * per_worker - 1);
    REQUIRE(g_dropped_events.load() == 0);
    events = CollectQueuedEvents();
    REQUIRE(events.size() == 11);
    occurrences.clear();
    for (const auto& event : events) occurrences.push_back(event.reason_occurrence);
    std::sort(occurrences.begin(), occurrences.end());
    REQUIRE(occurrences == expected);
    REQUIRE(header.bytes() == before);

    // A real allocation failure is counted as dropped, never as intentional
    // suppression, and does not prevent the underlying decline being counted.
    ResetAdapterState();
    g_extended_archive_storage = true;
    for (const auto& unused : g_events) {
        (void)unused;
        QueueEvent("TEST", "fill-pool", header.address(), 0, 0, CapacitySource::Unavailable);
    }
    REQUIRE(!TryRebuild(header.address(), first, nullptr));
    REQUIRE(g_declines.load() == 1 && g_extended_declines.load() == 1);
    REQUIRE(g_suppressed_extended_events.load() == 0);
    REQUIRE(g_dropped_events.load() == 1);
    REQUIRE(CollectQueuedEvents().size() == sizeof(g_events) / sizeof(g_events[0]));
}

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

namespace detour = freezefix::detour;

class IdentityFixture {
public:
    TestRegion code{4096};
    std::vector<detour_test::Site> sites;
    std::vector<detour::PatchWindow> windows;
    std::vector<std::uint8_t> native;
    std::vector<std::uint32_t> prefix_crc;
    freezefix::CodeIdentity identity{};

    explicit IdentityFixture(const char* routine) {
        for (const auto& site : detour_test::Sites()) {
            if (std::strcmp(routine, site.routine) != 0) continue;
            sites.push_back(site);
            windows.push_back(site.window);
        }
        REQUIRE(!sites.empty());
        native.resize(sites.front().routine_length, 0xCC);
        for (const auto& window : windows)
            std::copy_n(window.original.begin(), window.length, native.begin() + window.offset);
        std::uint32_t crc = 0;
        for (const auto byte : native) {
            crc = detour::Crc32Step(crc, byte);
            prefix_crc.push_back(crc);
        }
        identity = {routine, 0x42, native.size(), {}, prefix_crc.data(), prefix_crc.size(),
                    windows.data(), windows.size()};
        REQUIRE(Sha256(native, identity.sha256));
        code.fill(0xCC);
        std::memcpy(reinterpret_cast<void*>(code.address()), native.data(), native.size());
        code.protect(PAGE_EXECUTE_READWRITE);
    }

    std::uintptr_t relay(std::size_t index = 0) const { return code.address() + 0x400 + index * 0x100; }
    std::uintptr_t stub(std::size_t index = 0) const { return code.address() + 0x440 + index * 0x100; }

    void detour_all(bool use_source_stubs) {
        const auto helper = reinterpret_cast<std::uintptr_t>(&NativeInsertStub);
        for (std::size_t index = 0; index < sites.size(); ++index) {
            const auto& site = sites[index];
            const auto entry = code.address() + site.window.offset;
            const auto distance = static_cast<std::int32_t>(relay(index) - entry - 5);
            std::array<std::uint8_t, 5> branch{{0xE9, 0, 0, 0, 0}};
            std::memcpy(branch.data() + 1, &distance, sizeof(distance));
            std::memset(reinterpret_cast<void*>(entry), 0x90, site.window.length);
            AdapterWrite(entry, branch);
            std::array<std::uint8_t, 14> indirect{{0xFF, 0x25, 0, 0, 0, 0}};
            const auto destination = use_source_stubs ? stub(index) : helper;
            std::memcpy(indirect.data() + 6, &destination, sizeof(destination));
            AdapterWrite(relay(index), indirect);
            if (use_source_stubs) {
                const auto bytes = detour_test::Stub(site, helper, entry + site.window.length);
                std::memcpy(reinterpret_cast<void*>(stub(index)), bytes.data(), bytes.size());
            }
        }
    }

    std::vector<std::uint8_t> observed() const {
        std::vector<std::uint8_t> bytes(native.size());
        REQUIRE(ReadMemory(code.address(), bytes.data(), bytes.size()));
        return bytes;
    }
};

void actual_identity_validation_accepts_native_and_compatible_module_detours() {
    for (const char* routine : {"archive_add", "archive_lookup"}) {
        for (const bool use_source_stubs : {false, true}) {
            ResetAdapterState();
            IdentityFixture fixture(routine);
            CodeContract native;
            IdentityDiagnostic native_diagnostic;
            REQUIRE(ValidateIdentity(fixture.identity, fixture.code.address(), fixture.observed(),
                                     native, native_diagnostic));
            REQUIRE(native_diagnostic.accepted && !native_diagnostic.detoured);
            REQUIRE(native_diagnostic.first_difference == detour::kNoDifference);
            REQUIRE(native.detour_bytes.empty());
            REQUIRE(native.modules.empty());

            fixture.detour_all(use_source_stubs);
            const auto before = fixture.code.bytes();
            CodeContract compatible;
            IdentityDiagnostic diagnostic;
            REQUIRE(ValidateIdentity(fixture.identity, fixture.code.address(), fixture.observed(),
                                     compatible, diagnostic));
            REQUIRE(diagnostic.accepted && diagnostic.detoured);
            REQUIRE(diagnostic.actual_hashed && diagnostic.normalized_hashed);
            REQUIRE(diagnostic.actual != fixture.identity.sha256);
            REQUIRE(diagnostic.normalized == fixture.identity.sha256);
            REQUIRE(diagnostic.first_difference == fixture.windows.front().offset);
            REQUIRE(diagnostic.remaining_difference == detour::kNoDifference);
            REQUIRE(compatible.expected == fixture.observed());
            REQUIRE(!compatible.detour_bytes.empty());
            REQUIRE(compatible.modules.size() == fixture.windows.size());
            const auto helper = reinterpret_cast<std::uintptr_t>(&NativeInsertStub);
            const auto module_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
            for (const auto& module : compatible.modules) {
                REQUIRE(module.base == module_base);
                REQUIRE(module.endpoint == helper);
                REQUIRE(module.path[0] != L'\0');
            }
            const auto line = FormatIdentityDiagnostic(fixture.identity, diagnostic);
            REQUIRE(line.find("result=accepted-detour") != std::string::npos);
            REQUIRE(line.find("expected_sha256=" + DigestText(fixture.identity.sha256)) != std::string::npos);
            REQUIRE(line.find("actual_sha256=" + DigestText(diagnostic.actual)) != std::string::npos);
            REQUIRE(line.find("first_diff=+" + HexText(fixture.windows.front().offset)) != std::string::npos);
            REQUIRE(line.find("target_module=" + ModuleName(compatible.modules.front()) + "+" +
                              HexText(helper - module_base)) != std::string::npos);
            REQUIRE(fixture.code.bytes() == before); // Normalization never changes executable memory.
            g_code_contracts = {compatible};
            g_contracts_ready = true;
            g_extended_archive_storage = true;
            REQUIRE(CodeContractsUnchanged());
            NativeFixture table;
            REQUIRE(TryRebuild(table.self(), table.incoming, &table.keys_reference));
        }
    }
}

void actual_identity_validation_rejects_unrelated_changes_and_untrusted_endpoints() {
    for (const char* routine : {"archive_add", "archive_lookup"}) {
        for (unsigned fault = 0; fault < 11; ++fault) {
            ResetAdapterState();
            IdentityFixture fixture(routine);
            fixture.detour_all(true);
            const auto& site = fixture.sites.front();
            switch (fault) {
            case 0: AdapterWrite(fixture.code.address(), std::uint8_t{0xCD}); break; // Outside every window.
            case 1: AdapterWrite(fixture.code.address() + site.window.offset, std::uint8_t{0xE8}); break;
            case 2: AdapterWrite(fixture.code.address() + site.window.offset + 5, std::uint8_t{0xCC}); break;
            case 3: AdapterWrite(fixture.relay() + 6, std::uintptr_t{0}); break;
            case 4: { // A relay cycle cannot establish a module endpoint.
                const std::array<std::uint8_t, 5> self_jump{{0xE9, 0xFB, 0xFF, 0xFF, 0xFF}};
                AdapterWrite(fixture.relay(), self_jump);
                break;
            }
            case 5: {
                const auto anonymous = fixture.code.address() + 0xE00;
                std::memset(reinterpret_cast<void*>(anonymous), 0x90, 128);
                AdapterWrite(fixture.relay() + 6, anonymous);
                break;
            }
            case 6: fixture.code.protect(PAGE_READONLY); break; // Readable anonymous data cannot be code.
            case 7: AdapterWrite(fixture.stub(), std::uint8_t{0x49}); break;
            case 8:
                AdapterWrite(fixture.stub() + site.return_offset,
                             fixture.code.address() + site.window.offset + site.window.length + 1);
                break;
            case 10: {
                const auto nested_address = fixture.code.address() + 0xD00;
                const auto nested = detour_test::Stub(site,
                    reinterpret_cast<std::uintptr_t>(&NativeInsertStub),
                    fixture.code.address() + site.window.offset + site.window.length);
                std::memcpy(reinterpret_cast<void*>(nested_address), nested.data(), nested.size());
                AdapterWrite(fixture.stub() + site.helper_offset, nested_address);
                break;
            }
            }
            const auto before = fixture.code.bytes();
            CodeContract rejected;
            IdentityDiagnostic diagnostic;
            auto observed = fixture.observed();
            if (fault == 9) observed.pop_back();
            REQUIRE(!ValidateIdentity(fixture.identity, fixture.code.address(), observed,
                                      rejected, diagnostic));
            REQUIRE(!diagnostic.accepted);
            REQUIRE(rejected.expected.empty());
            const auto line = FormatIdentityDiagnostic(fixture.identity, diagnostic);
            REQUIRE(line.find("result=rejected") != std::string::npos);
            REQUIRE(line.find("expected_sha256=" + DigestText(fixture.identity.sha256)) != std::string::npos);
            REQUIRE(line.find("actual_sha256=" + DigestText(diagnostic.actual)) != std::string::npos);
            if (fault == 0) {
                REQUIRE(diagnostic.first_difference == 0);
                REQUIRE(diagnostic.remaining_difference == 0);
                REQUIRE(line.find("first_diff=+0x0") != std::string::npos);
                REQUIRE(line.find("remaining_diff=+0x0") != std::string::npos);
            }
            REQUIRE(fixture.code.bytes() == before);
        }
    }
}

void retained_detour_evidence_blocks_commit_after_any_code_or_pointer_change() {
    for (unsigned fault = 0; fault < 6; ++fault) {
        ResetAdapterState();
        IdentityFixture fixture("archive_add");
        fixture.detour_all(true);
        CodeContract contract;
        IdentityDiagnostic diagnostic;
        REQUIRE(ValidateIdentity(fixture.identity, fixture.code.address(), fixture.observed(), contract, diagnostic));
        g_code_contracts = {contract};
        g_contracts_ready = true;
        g_extended_archive_storage = true;
        REQUIRE(CodeContractsUnchanged());
        NativeFixture table;
        const SourceBytes before(table);
        const auto& site = fixture.sites.front();
        switch (fault) {
        case 0: AdapterWrite(fixture.code.address(), std::uint8_t{0xCD}); break;
        case 1: AdapterWrite(fixture.code.address() + site.window.offset, std::uint8_t{0xE8}); break;
        case 2: AdapterWrite(fixture.relay() + 1, std::uint8_t{0x24}); break;
        case 3:
            AdapterWrite(fixture.relay() + 6, reinterpret_cast<std::uintptr_t>(&NativeInsertStub));
            break; // Still resolves to a module, but differs from the accepted pointer cell.
        case 4: AdapterWrite(fixture.stub(), std::uint8_t{0x49}); break;
        case 5: fixture.code.protect(PAGE_READONLY); break;
        }
        REQUIRE(!CodeContractsUnchanged());
        REQUIRE(!TryRebuild(table.self(), table.incoming, &table.keys_reference));
        REQUIRE(g_rebuilds.load() == 0);
        before.unchanged(table);
    }
}

// Slot 255 is the extended-storage pointer once Daytripper4 is active, so the
// adapter must read indices 255 and above through the verified vector layout
// instead of treating the pointer as a key.
void extended_storage_reads_keys_through_the_vector_layout() {
    for (const std::uint32_t existing : {254U, 255U}) {
        ResetAdapterState();
        NativeFixture fixture;
        const NativeTable header{0xAABBCCDDEEFF0011ULL, fixture.table.address(), 512, 511,
                                 512 - existing, 511};
        AdapterWrite(fixture.self(), header);
        AdapterWrite(fixture.self() + freezefix::kArchiveCountOffset, existing);
        std::vector<archive::Key> keys;
        std::array<archive::Entry, 512> entries{};
        for (std::uint32_t index = 0; index <= existing; ++index) {
            keys.push_back({index * 512, index + 1, 1});
            if (index < existing) entries[index] = {0xFFFF, static_cast<std::uint16_t>(index)};
        }
        entries[0].next = 0; // Broken topology, complete physical membership.
        const std::uint32_t inlineCount =
            keys.size() < 255 ? static_cast<std::uint32_t>(keys.size()) : 255U;
        std::memcpy(reinterpret_cast<void*>(fixture.keys_address()), keys.data(),
                    inlineCount * sizeof(keys[0]));
        TestRegion vectorObject(0x40);
        TestRegion vectorData(0x1000);
        if (keys.size() > 255) {
            const std::uint32_t extendedCount = static_cast<std::uint32_t>(keys.size()) - 255U;
            std::memcpy(reinterpret_cast<void*>(vectorData.address()), keys.data() + 255,
                        extendedCount * sizeof(keys[0]));
            const std::array<std::uintptr_t, 3> fields{
                vectorData.address(),
                vectorData.address() + extendedCount * sizeof(keys[0]),
                vectorData.address() + vectorData.size()};
            AdapterWrite(vectorObject.address(), fields);
            AdapterWrite(fixture.keys_address() + 255 * sizeof(keys[0]), vectorObject.address());
        }
        std::memcpy(reinterpret_cast<void*>(fixture.table.address()), entries.data(), sizeof(entries));
        g_extended_archive_storage = true;
        CapturedIndex captured;
        REQUIRE(CaptureIndex(fixture.self(), existing, &fixture.keys_reference, captured));
        REQUIRE(captured.keys.size() == keys.size());
        REQUIRE(std::memcmp(captured.keys.data(), keys.data(), keys.size() * sizeof(keys[0])) == 0);
        REQUIRE(archive::Analyze(captured.view()) == archive::Validation::Rebuildable);
        REQUIRE(TryRebuild(fixture.self(), existing, &fixture.keys_reference));
        REQUIRE(fixture.header().available == 512 - (existing + 1));
    }
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

// A failed restore leaves the window patched, so the stub it calls must stay
// resident. Freeing it would leave a dangling code pointer in the engine.
void rollback_failure_retains_the_referenced_stub() {
    ResetAdapterState();
    TestRegion code(64);
    code.fill(0xCC);
    const std::array<std::uint8_t, 7> original{0x42, 0x8B, 0x1C, 0x88, 0x4D, 0x8B, 0xF0};
    std::memcpy(reinterpret_cast<void*>(code.address()), original.data(), original.size());
    std::array<std::uint8_t, 7> expected{};
    std::memcpy(expected.data(), original.data(), original.size());
    const auto stub = freezefix::native::BuildIncomingStub(
        reinterpret_cast<std::uintptr_t>(&FreezeFixKeyAddress));

    PreparedPatch prepared;
    REQUIRE(PrepareNativePatch(code.address(), original.data(), original.size(), stub,
                               expected.data(), prepared));
    REQUIRE(CommitNativePatch(prepared));
    REQUIRE(prepared.committed);
    REQUIRE(std::memcmp(reinterpret_cast<const void*>(code.address()), original.data(),
                        original.size()) != 0);

    g_force_rollback_failure = true;
    REQUIRE(!RollbackNativePatch(prepared));
    REQUIRE(prepared.committed);
    ReleaseUnreferencedStubs(&prepared, 1);
    REQUIRE(prepared.stub != nullptr);

    g_force_rollback_failure = false;
    REQUIRE(RollbackNativePatch(prepared));
    REQUIRE(!prepared.committed);
    REQUIRE(std::memcmp(reinterpret_cast<const void*>(code.address()), original.data(),
                        original.size()) == 0);
    ReleaseUnreferencedStubs(&prepared, 1);
    REQUIRE(prepared.stub == nullptr);
}

// A failed commit followed by a failed restore must report the residual windows
// and keep their stubs, so the caller can say the engine is partially patched.
void partial_installation_reports_residual_windows() {
    ResetAdapterState();
    TestRegion code(128);
    code.fill(0xCC);
    const std::array<std::uint8_t, 7> original{0x42, 0x8B, 0x1C, 0x88, 0x4D, 0x8B, 0xF0};
    const auto stub = freezefix::native::BuildIncomingStub(
        reinterpret_cast<std::uintptr_t>(&FreezeFixKeyAddress));

    std::array<PreparedPatch, 3> prepared{};
    for (std::size_t i = 0; i < prepared.size(); ++i) {
        const auto site = code.address() + i * 16;
        std::memcpy(reinterpret_cast<void*>(site), original.data(), original.size());
        std::array<std::uint8_t, 7> expected{};
        REQUIRE(PrepareNativePatch(site, original.data(), original.size(), stub,
                                   expected.data(), prepared[i]));
        // The third window is prepared but its commit "fails", so it is never
        // patched; only the first two are.
        if (i < 2) REQUIRE(CommitNativePatch(prepared[i]));
    }

    // The third commit fails; the first two cannot be restored.
    g_force_rollback_failure = true;
    const unsigned residual = HandleCommitFailure(prepared.data(), prepared.size(), 2);
    g_force_rollback_failure = false;

    REQUIRE(residual == 2);
    REQUIRE(prepared[0].committed);
    REQUIRE(prepared[1].committed);
    REQUIRE(prepared[0].stub != nullptr);
    REQUIRE(prepared[1].stub != nullptr);

    // A clean rollback reports nothing residual and frees every stub.
    for (auto& patch : prepared) REQUIRE(RollbackNativePatch(patch));
    ReleaseUnreferencedStubs(prepared.data(), prepared.size());
    for (const auto& patch : prepared) REQUIRE(patch.stub == nullptr);
}

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
        {"native and compatible function identities", actual_identity_validation_accepts_native_and_compatible_module_detours},
        {"unrelated patches and anonymous endpoints rejected", actual_identity_validation_rejects_unrelated_changes_and_untrusted_endpoints},
        {"retained detour evidence prevents changed-code commit", retained_detour_evidence_blocks_commit_after_any_code_or_pointer_change},
        {"extended archive storage boundary", extended_storage_reads_keys_through_the_vector_layout},
        {"bounded raw header decline diagnostics", unsupported_storage_diagnostics_read_only_the_exact_raw_header},
        {"sampled declines preserve counters and event capacity", repeated_unsupported_declines_preserve_counters_and_event_capacity},
        {"Windows BCrypt SHA-256", bcrypt_hashes_the_standard_sha256_vector},
        {"rollback failure retains the referenced stub", rollback_failure_retains_the_referenced_stub},
        {"partial installation reports residual windows", partial_installation_reports_residual_windows},
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
