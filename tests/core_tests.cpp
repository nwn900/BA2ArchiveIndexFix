#include "address_library.h"
#include "archive_index.h"
#include "install_lifecycle.h"
#include "monitor_core.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

void check(bool passed, const char* expression, int line) {
    if (!passed) {
        throw std::runtime_error(std::string("line ") + std::to_string(line) + ": " + expression);
    }
}
#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

void elapsed_time_is_bounded() {
    CHECK(freezefix::elapsed_ms(120, 100) == 20);
    CHECK(freezefix::elapsed_ms(100, 100) == 0);
    CHECK(freezefix::elapsed_ms(99, 100) == 0);
    CHECK(freezefix::elapsed_ms(0, std::numeric_limits<std::uint64_t>::max()) == 0);
    CHECK(freezefix::elapsed_ms(std::numeric_limits<std::uint64_t>::max(), 0) ==
          std::numeric_limits<std::uint64_t>::max());
}

void stale_tokens_cannot_change_reused_slots() {
    freezefix::MonitorCore<1> monitor;
    const freezefix::Token empty{};
    CHECK(!empty);
    CHECK(!monitor.is_active(empty));
    CHECK(!monitor.end(empty));
    CHECK(!monitor.try_mark_reported(empty));
    const auto old = monitor.begin(12, 0x1110, 100);
    CHECK(old);
    freezefix::Snapshot snapshot{};
    CHECK(!monitor.try_snapshot(monitor.capacity(), snapshot));
    CHECK(!monitor.end(freezefix::Token{monitor.capacity(), 0}));
    CHECK(!monitor.end(freezefix::Token{old.slot, old.generation | 1}));
    CHECK(monitor.is_active(old));
    CHECK(monitor.try_snapshot(old.slot, snapshot));
    CHECK(snapshot.thread_id == 12);
    CHECK(snapshot.object == 0x1110);
    CHECK(snapshot.since_ms == 100);
    CHECK(!snapshot.reported);
    CHECK(monitor.try_mark_reported(old));
    CHECK(!monitor.try_mark_reported(old));
    CHECK(monitor.try_snapshot(old.slot, snapshot));
    CHECK(snapshot.reported);
    CHECK(monitor.end(old));
    CHECK(!monitor.is_active(old));
    CHECK(!monitor.try_snapshot(old.slot, snapshot));

    const auto replacement = monitor.begin(1232, 0x2220, 200);
    CHECK(replacement);
    CHECK(replacement.slot == old.slot);
    CHECK(replacement.generation != old.generation);
    CHECK(!monitor.end(old));
    CHECK(!monitor.try_mark_reported(old));
    CHECK(!monitor.is_active(old));
    CHECK(monitor.is_active(replacement));
    CHECK(monitor.try_snapshot(replacement.slot, snapshot));
    CHECK(snapshot.thread_id == 1232);
    CHECK(snapshot.object == 0x2220);
    CHECK(snapshot.since_ms == 200);
    CHECK(!snapshot.reported);
    CHECK(monitor.end(replacement));
    CHECK(!monitor.end(replacement));
}

void recursive_waits_and_exhaustion_preserve_active_records() {
    freezefix::MonitorCore<2> monitor;
    const auto outer = monitor.begin(7, 0x1000, 10);
    const auto inner = monitor.begin(7, 0x2000, 20);
    CHECK(outer);
    CHECK(inner);
    CHECK(outer.slot != inner.slot);
    CHECK(!monitor.begin(8, 0x3000, 30));
    CHECK(monitor.is_active(outer));
    CHECK(monitor.is_active(inner));
    freezefix::Snapshot snapshot{};
    CHECK(monitor.try_snapshot(outer.slot, snapshot));
    CHECK(snapshot.object == 0x1000);
    CHECK(snapshot.since_ms == 10);
    CHECK(monitor.end(inner));
    CHECK(monitor.is_active(outer));
    const auto next = monitor.begin(8, 0x3000, 30);
    CHECK(next);
    CHECK(!monitor.end(inner));
    CHECK(monitor.is_active(next));
    CHECK(monitor.end(next));
    CHECK(monitor.end(outer));
}

void legacy_hash_collisions_keep_both_threads() {
    freezefix::MonitorCore<512> monitor;
    // These two thread IDs collided in the former single-slot tracker.
    const auto first = monitor.begin(12, 0x1110, 10);
    const auto second = monitor.begin(1232, 0x2220, 20);
    CHECK(first);
    CHECK(second);
    CHECK(first.slot != second.slot);
    CHECK(monitor.end(second));
    CHECK(monitor.is_active(first));
    freezefix::Snapshot snapshot{};
    CHECK(monitor.try_snapshot(first.slot, snapshot));
    CHECK(snapshot.thread_id == 12);
    CHECK(snapshot.object == 0x1110);
    CHECK(monitor.end(first));
}

void reporting_is_once_per_invocation_under_contention() {
    freezefix::MonitorCore<1> monitor;
    const auto token = monitor.begin(1, 0x1000, 0);
    CHECK(token);
    std::atomic<unsigned> winners{0};
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < 8; ++i) {
        workers.emplace_back([&] {
            for (unsigned attempt = 0; attempt < 100; ++attempt) {
                if (monitor.try_mark_reported(token)) ++winners;
            }
        });
    }
    for (auto& worker : workers) worker.join();
    CHECK(winners.load() == 1);
    CHECK(monitor.is_active(token));
    CHECK(monitor.end(token));
}

void concurrent_snapshots_never_mix_invocations() {
    freezefix::MonitorCore<16> monitor;
    std::atomic<unsigned> completed{0};
    std::atomic<unsigned> tracked{0};
    std::atomic<unsigned> observed{0};
    std::atomic<unsigned> first_observed{0};
    std::atomic<bool> malformed{false};
    bool timed_out = false;
    std::vector<std::thread> workers;
    for (std::uint32_t id = 1; id <= 4; ++id) {
        workers.emplace_back([&, id] {
            bool first = true;
            for (std::uint64_t sequence = 1; sequence <= 10000; ++sequence) {
                const auto token = monitor.begin(id,
                    static_cast<std::uintptr_t>(id * 1000000ULL + sequence), sequence);
                if (!token) continue;  // A bounded monitor may drop diagnostics under contention.
                ++tracked;
                // Hold each producer's first record until the reader samples it;
                // the test cannot pass without exercising concurrent observation.
                if (first) {
                    while ((first_observed.load() & (1U << (id - 1))) == 0)
                        std::this_thread::yield();
                    first = false;
                }
                if ((sequence & 31U) == 0) std::this_thread::yield();
                if (!monitor.end(token)) malformed.store(true);
            }
            ++completed;
        });
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (completed.load() != 4) {
        if (std::chrono::steady_clock::now() >= deadline) {
            timed_out = true;
            first_observed.store(0xF);
            break;
        }
        for (std::size_t slot = 0; slot < monitor.capacity(); ++slot) {
            freezefix::Snapshot snapshot{};
            if (!monitor.try_snapshot(slot, snapshot)) continue;
            ++observed;
            if (snapshot.thread_id < 1 || snapshot.thread_id > 4 ||
                snapshot.since_ms < 1 || snapshot.since_ms > 10000 ||
                snapshot.object != snapshot.thread_id * 1000000ULL + snapshot.since_ms) {
                malformed.store(true);
                first_observed.store(0xF);  // Let producers finish so corruption reports as a failure.
            } else {
                first_observed.fetch_or(1U << (snapshot.thread_id - 1));
            }
        }
    }
    for (auto& worker : workers) worker.join();
    CHECK(!timed_out);
    CHECK(!malformed.load());
    CHECK(tracked.load() != 0);
    CHECK(observed.load() != 0);
    for (std::size_t slot = 0; slot < monitor.capacity(); ++slot) {
        freezefix::Snapshot snapshot{};
        CHECK(!monitor.try_snapshot(slot, snapshot));
    }
}

using Mapping = std::pair<std::uint64_t, std::uint64_t>;

void append_u64(std::string& bytes, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) {
        bytes.push_back(static_cast<char>((value >> (i * 8)) & 0xFFU));
    }
}

std::string address_file(const std::vector<Mapping>& mappings) {
    std::string bytes;
    append_u64(bytes, mappings.size());
    for (const auto& mapping : mappings) {
        append_u64(bytes, mapping.first);
        append_u64(bytes, mapping.second);
    }
    return bytes;
}

freezefix::AddressError parse(const std::string& bytes, std::uint64_t file_size,
                            freezefix::Addresses& addresses) {
    std::istringstream input(bytes, std::ios::in | std::ios::binary);
    return freezefix::read_address_library(input, file_size, addresses);
}

void expect_rejected(const std::string& bytes, freezefix::AddressError expected) {
    freezefix::Addresses addresses{123, 456};
    CHECK(parse(bytes, bytes.size(), addresses) == expected);
    CHECK(addresses.lock_read == 0);
    CHECK(addresses.hash_insert == 0);
}

void address_library_requires_both_actual_targets() {
    auto bytes = address_file({{100, 0x500},
        {freezefix::kHashInsertId, freezefix::kHashInsertRva},
        {freezefix::kLockReadId, freezefix::kLockReadRva},
        {2000000, 0x700}});
    freezefix::Addresses addresses{};
    CHECK(parse(bytes, bytes.size(), addresses) == freezefix::AddressError::none);
    CHECK(addresses.lock_read == freezefix::kLockReadRva);
    CHECK(addresses.hash_insert == freezefix::kHashInsertRva);

    expect_rejected(address_file({{freezefix::kLockReadId, freezefix::kLockReadRva}}),
                    freezefix::AddressError::missing_required_id);
    expect_rejected(address_file({{freezefix::kHashInsertId, freezefix::kHashInsertRva}}),
                    freezefix::AddressError::missing_required_id);

    // This exact five-ID set satisfied the old test while omitting the hash-walk target.
    std::vector<Mapping> legacy{{1573164, 0x1b10930}, {336186, 0x1b109b0},
        {1526234, 0x2110ad0}, {1191277, 0x21110a0}, {1425657, 0x244d0}};
    std::sort(legacy.begin(), legacy.end());
    expect_rejected(address_file(legacy), freezefix::AddressError::missing_required_id);
}

void address_library_rejects_ambiguous_or_wrong_mappings() {
    expect_rejected(address_file({
        {freezefix::kHashInsertId, freezefix::kHashInsertRva},
        {freezefix::kHashInsertId, freezefix::kHashInsertRva},
        {freezefix::kLockReadId, freezefix::kLockReadRva}}),
        freezefix::AddressError::unsorted_ids);
    expect_rejected(address_file({
        {freezefix::kLockReadId, freezefix::kLockReadRva},
        {freezefix::kHashInsertId, freezefix::kHashInsertRva}}),
        freezefix::AddressError::unsorted_ids);
    expect_rejected(address_file({
        {freezefix::kHashInsertId, freezefix::kHashInsertRva + 1},
        {freezefix::kLockReadId, freezefix::kLockReadRva}}),
        freezefix::AddressError::unexpected_rva);
    expect_rejected(address_file({
        {freezefix::kHashInsertId, freezefix::kHashInsertRva},
        {freezefix::kLockReadId, freezefix::kLockReadRva + 1}}),
        freezefix::AddressError::unexpected_rva);
}

void address_library_rejects_incomplete_and_oversized_files() {
    expect_rejected({}, freezefix::AddressError::invalid_size);
    expect_rejected(std::string(7, '\0'), freezefix::AddressError::invalid_size);
    expect_rejected(address_file({}), freezefix::AddressError::invalid_count);
    std::string huge;
    append_u64(huge, 4000001);
    expect_rejected(huge, freezefix::AddressError::invalid_count);

    auto valid = address_file({
        {freezefix::kHashInsertId, freezefix::kHashInsertRva},
        {freezefix::kLockReadId, freezefix::kLockReadRva}});
    expect_rejected(valid + 'x', freezefix::AddressError::invalid_size);
    expect_rejected(valid.substr(0, valid.size() - 1), freezefix::AddressError::invalid_size);
    freezefix::Addresses addresses{123, 456};
    CHECK(parse(valid.substr(0, 8), valid.size(), addresses) == freezefix::AddressError::io);
    CHECK(addresses.lock_read == 0);
    CHECK(addresses.hash_insert == 0);
}

void code_ranges_and_loop_signatures_fail_closed() {
    CHECK(freezefix::contains_range(100, 99, 1));
    CHECK(!freezefix::contains_range(100, 100, 1));
    CHECK(!freezefix::contains_range(100, 99, 2));
    CHECK(!freezefix::contains_range(100, 101, 1));
    CHECK(!freezefix::contains_range(std::numeric_limits<std::uint64_t>::max(),
          std::numeric_limits<std::uint64_t>::max() - 3, 4));

    // Encodes the disassembled mov/movzx/cmp/jne loop, not a generated signature.
    const std::vector<std::uint8_t> loop{
        0x44, 0x8B, 0xC9, 0x0F, 0xB7, 0x0C, 0x8A, 0x3B, 0xCB, 0x75, 0xF5};
    CHECK(freezefix::matches_hash_loop(loop.data(), loop.size()));
    auto alternate_cmp = loop;
    alternate_cmp[7] = 0x39;
    alternate_cmp[8] = 0xD9;
    CHECK(!freezefix::matches_hash_loop(alternate_cmp.data(), alternate_cmp.size()));
    CHECK(!freezefix::matches_hash_loop(nullptr, loop.size()));
    for (std::size_t size = 0; size < loop.size(); ++size) {
        CHECK(!freezefix::matches_hash_loop(loop.data(), size));
    }
    for (std::size_t byte = 0; byte < loop.size(); ++byte) {
        auto changed = loop;
        changed[byte] ^= 1;
        CHECK(!freezefix::matches_hash_loop(changed.data(), changed.size()));
    }
}

struct FakeSetup {
    freezefix::InstallStage fail_at = freezefix::InstallStage::installed;
    bool can_stop = true;
    bool can_remove = true;
    bool can_uninitialize = true;
    bool partial_enable = false;
    bool initialized = false;
    bool hook = false;
    bool worker = false;
    bool enabled = false;
    bool invalid_sequence = false;
    unsigned uninitialize_calls = 0;

    bool initialize() {
        if (fail_at == freezefix::InstallStage::initialize) return false;
        initialized = true;
        return true;
    }
    bool create_hook() {
        if (!initialized) invalid_sequence = true;
        if (fail_at == freezefix::InstallStage::create_hook) return false;
        hook = true;
        return true;
    }
    bool start_watchdog() {
        if (!initialized || !hook || enabled) invalid_sequence = true;
        if (fail_at == freezefix::InstallStage::start_watchdog) return false;
        worker = true;
        return true;
    }
    bool enable_hook() {
        if (!initialized || !hook || !worker) invalid_sequence = true;
        if (fail_at == freezefix::InstallStage::enable_hook) {
            enabled = partial_enable;
            return false;
        }
        enabled = true;
        return true;
    }
    bool any_hook_enabled() const { return enabled; }
    bool stop_watchdog() {
        if (!can_stop) return false;
        worker = false;
        return true;
    }
    bool remove_hook() {
        if (!can_remove) return false;
        hook = false;
        enabled = false;
        return true;
    }
    bool uninitialize() {
        ++uninitialize_calls;
        if (hook || enabled) invalid_sequence = true;
        if (!can_uninitialize) return false;
        initialized = false;
        return true;
    }
};

void installation_orders_resources_and_rolls_back_each_failure() {
    FakeSetup success;
    const auto installed = freezefix::install_observer(success);
    CHECK(installed);
    CHECK(installed.rollback_ok);
    CHECK(success.initialized && success.hook && success.worker && success.enabled);
    CHECK(!success.invalid_sequence);

    const freezefix::InstallStage failures[]{freezefix::InstallStage::initialize,
        freezefix::InstallStage::create_hook, freezefix::InstallStage::start_watchdog,
        freezefix::InstallStage::enable_hook};
    for (const auto failure : failures) {
        FakeSetup setup;
        setup.fail_at = failure;
        const auto result = freezefix::install_observer(setup);
        CHECK(!result);
        CHECK(result.stage == failure);
        CHECK(result.rollback_ok);
        CHECK(!setup.initialized && !setup.hook && !setup.worker && !setup.enabled);
        CHECK(!setup.invalid_sequence);
    }
}

void failed_cleanup_preserves_live_trampoline_resources() {
    FakeSetup partial;
    partial.fail_at = freezefix::InstallStage::enable_hook;
    partial.partial_enable = true;
    const auto retained = freezefix::install_observer(partial);
    CHECK(!retained);
    CHECK(!retained.rollback_ok);
    CHECK(partial.initialized && partial.hook && partial.worker && partial.enabled);
    CHECK(partial.uninitialize_calls == 0);
    CHECK(!partial.invalid_sequence);

    for (const auto failure : {freezefix::InstallStage::start_watchdog,
                               freezefix::InstallStage::enable_hook}) {
        FakeSetup setup;
        setup.fail_at = failure;
        setup.can_remove = false;
        const auto result = freezefix::install_observer(setup);
        CHECK(!result);
        CHECK(!result.rollback_ok);
        CHECK(setup.initialized && setup.hook);
        CHECK(setup.uninitialize_calls == 0);
        CHECK(!setup.invalid_sequence);
    }

    FakeSetup stop_failure;
    stop_failure.fail_at = freezefix::InstallStage::enable_hook;
    stop_failure.can_stop = false;
    CHECK(!freezefix::install_observer(stop_failure).rollback_ok);
    CHECK(stop_failure.worker);
    CHECK(!stop_failure.enabled);
    CHECK(!stop_failure.invalid_sequence);

    FakeSetup uninitialize_failure;
    uninitialize_failure.fail_at = freezefix::InstallStage::create_hook;
    uninitialize_failure.can_uninitialize = false;
    CHECK(!freezefix::install_observer(uninitialize_failure).rollback_ok);
    CHECK(uninitialize_failure.initialized);
    CHECK(!uninitialize_failure.hook && !uninitialize_failure.worker);
}

namespace archive = freezefix::archive;
constexpr std::uint16_t kEnd = 0xFFFF;

bool same_key(const archive::Key& first, const archive::Key& second) {
    return first.word0 == second.word0 && first.word1 == second.word1 && first.word2 == second.word2;
}

bool same_entries(const std::vector<archive::Entry>& first,
                  const std::vector<archive::Entry>& second) {
    return first.size() == second.size() && std::equal(first.begin(), first.end(), second.begin(),
        [](const archive::Entry& a, const archive::Entry& b) {
            return a.index == b.index && a.next == b.next;
        });
}

bool same_keys(const std::vector<archive::Key>& first, const std::vector<archive::Key>& second) {
    return first.size() == second.size() &&
        std::equal(first.begin(), first.end(), second.begin(), same_key);
}

// Independent oracle transcribed from the recovered archive Find routine: a
// bucket holds a member index in its upper word and a next slot in its lower
// word. Equality uses all 12 bytes of the key. Production Analyze/BuildRepair
// are deliberately not used to decide whether a rebuilt table works.
int lookup_archive(const std::vector<archive::Entry>& entries,
                   const std::vector<archive::Key>& keys, const archive::Key& wanted) {
    const auto mask = static_cast<std::uint32_t>(entries.size() - 1);
    std::uint32_t position = wanted.word0 & mask;
    if (entries[position].index == kEnd) return -1;
    for (std::size_t steps = 0; steps < entries.size(); ++steps) {
        if (position >= entries.size()) return -2;
        const auto& entry = entries[position];
        if (entry.index >= keys.size()) return -2;
        if (same_key(keys[entry.index], wanted)) return entry.index;
        if (entry.next == kEnd) return -1;
        position = entry.next;
    }
    return -2;  // A bounded test oracle reports a cycle instead of hanging.
}

struct ArchiveFixture {
    std::vector<archive::Entry> entries;
    std::vector<archive::Key> keys;
    std::uint32_t existing = 0;
    std::uint32_t cursor = 0;

    archive::Snapshot snapshot() const {
        const auto capacity = static_cast<std::uint32_t>(entries.size());
        return {entries.data(), capacity, keys.data(), static_cast<std::uint32_t>(keys.size()),
            existing, capacity - 1, capacity - existing, cursor};
    }
};

ArchiveFixture archive_fixture(std::uint32_t capacity, std::vector<archive::Key> keys) {
    CHECK(!keys.empty());
    ArchiveFixture fixture;
    fixture.entries.resize(capacity);
    fixture.keys = std::move(keys);
    fixture.existing = static_cast<std::uint32_t>(fixture.keys.size() - 1);
    fixture.cursor = capacity - 1;
    CHECK(fixture.existing <= capacity);

    // Construct valid chains by grouping homes first, then allocating overflow
    // slots upwards. This differs from the engine's descending insertion and
    // displacement algorithm, and exercises valid non-canonical layouts.
    std::map<std::uint32_t, std::vector<std::uint16_t>> groups;
    for (std::uint32_t member = 0; member < fixture.existing; ++member) {
        groups[fixture.keys[member].word0 & (capacity - 1)].push_back(
            static_cast<std::uint16_t>(member));
    }
    for (const auto& group : groups) fixture.entries[group.first].index = group.second.front();
    std::uint32_t candidate = 0;
    for (const auto& group : groups) {
        std::uint32_t previous = group.first;
        for (std::size_t i = 1; i < group.second.size(); ++i) {
            while (candidate < capacity &&
                   (candidate == kEnd || fixture.entries[candidate].index != kEnd)) ++candidate;
            CHECK(candidate < capacity);
            fixture.entries[previous].next = static_cast<std::uint16_t>(candidate);
            fixture.entries[candidate].index = group.second[i];
            previous = candidate++;
        }
    }
    return fixture;
}

void assert_archive_members(const std::vector<archive::Entry>& entries,
                            const std::vector<archive::Key>& keys, std::size_t expected) {
    std::vector<unsigned> seen(expected, 0);
    for (const auto& entry : entries) {
        if (entry.index == kEnd) {
            CHECK(entry.next == kEnd);
            continue;
        }
        CHECK(entry.index < expected);
        ++seen[entry.index];
        CHECK(entry.next == kEnd || entry.next < entries.size());
    }
    for (std::size_t member = 0; member < expected; ++member) {
        CHECK(seen[member] == 1);
        CHECK(lookup_archive(entries, keys, keys[member]) == static_cast<int>(member));
    }
    CHECK(lookup_archive(entries, keys, archive::Key{0, 0xFFFFFFFF, 0xFFFFFFFF}) == -1);
}

std::vector<archive::Entry> rebuild_and_verify(const ArchiveFixture& fixture) {
    const auto before_entries = fixture.entries;
    const auto before_keys = fixture.keys;
    auto view = fixture.snapshot();
    std::vector<archive::Entry> staged(fixture.entries.size(), archive::Entry{0x1234, 0x4321});
    CHECK(archive::Analyze(view) == archive::Validation::Rebuildable);
    const auto result = archive::BuildRepair(view, staged.data(), staged.size());
    CHECK(result.status == archive::BuildStatus::Ready);
    CHECK(result.available == staged.size() - fixture.existing - 1);
    CHECK(result.lastFree < staged.size());
    CHECK(same_entries(fixture.entries, before_entries));
    CHECK(same_keys(fixture.keys, before_keys));
    assert_archive_members(staged, fixture.keys, fixture.keys.size());
    return staged;
}

void healthy_archive_tables_are_untouched() {
    for (auto fixture : {archive_fixture(8, {{0, 1, 1}, {8, 2, 1}, {3, 3, 1}, {16, 4, 1}}),
                         archive_fixture(8, {{1, 1, 1}}),
                         archive_fixture(8, {{0, 1, 1}, {0, 1, 2}, {0, 1, 3}}),
                         archive_fixture(8, {{0, 1, 1}, {8, 1, 1}, {16, 1, 1}})}) {
        const auto before = fixture.entries;
        std::vector<archive::Entry> staged(8, archive::Entry{0x1234, 0x4321});
        const auto before_staged = staged;
        CHECK(archive::Analyze(fixture.snapshot()) == archive::Validation::Healthy);
        const auto result = archive::BuildRepair(fixture.snapshot(), staged.data(), staged.size());
        CHECK(result.status == archive::BuildStatus::NotNeeded);
        CHECK(same_entries(staged, before_staged));
        CHECK(same_entries(fixture.entries, before));
        assert_archive_members(fixture.entries, fixture.keys, fixture.existing);
    }
}

void archive_cycles_and_disconnected_chains_preserve_every_member() {
    const auto valid = archive_fixture(8, {{0, 1, 1}, {8, 2, 1}, {3, 3, 1}, {16, 4, 1}});
    auto cycle = valid;
    cycle.entries[0].next = 0;
    rebuild_and_verify(cycle);
    auto disconnected = valid;
    disconnected.entries[0].next = kEnd;
    rebuild_and_verify(disconnected);
    auto foreign_chain = valid;
    foreign_chain.entries[0].next = 3;
    rebuild_and_verify(foreign_chain);
    auto outside = valid;
    outside.entries[0].next = 100;
    rebuild_and_verify(outside);
}

void rejected_archive_inputs_never_change_source_or_output() {
    const auto valid = archive_fixture(8, {{0, 1, 1}, {8, 2, 1}, {3, 3, 1}, {16, 4, 1}});
    auto reject = [](const ArchiveFixture& fixture, archive::Snapshot view) {
        const auto before_entries = fixture.entries;
        const auto before_keys = fixture.keys;
        std::vector<archive::Entry> staged(fixture.entries.size(), archive::Entry{0x1234, 0x4321});
        const auto before_staged = staged;
        const auto validation = archive::Analyze(view);
        CHECK(validation != archive::Validation::Healthy);
        CHECK(validation != archive::Validation::Rebuildable);
        CHECK(archive::BuildRepair(view, staged.data(), staged.size()).status ==
              archive::BuildStatus::Rejected);
        CHECK(same_entries(fixture.entries, before_entries));
        CHECK(same_keys(fixture.keys, before_keys));
        CHECK(same_entries(staged, before_staged));
    };
    auto duplicate_member = valid;
    duplicate_member.entries[1].index = 0;
    reject(duplicate_member, duplicate_member.snapshot());
    auto foreign_member = valid;
    foreign_member.entries[1].index = static_cast<std::uint16_t>(valid.existing);
    reject(foreign_member, foreign_member.snapshot());
    auto missing_member = valid;
    missing_member.entries[1] = {};
    reject(missing_member, missing_member.snapshot());
    auto malformed_empty = valid;
    malformed_empty.entries[2] = {0, kEnd};
    reject(malformed_empty, malformed_empty.snapshot());
    auto duplicate_key = valid;
    duplicate_key.keys.back() = duplicate_key.keys.front();
    reject(duplicate_key, duplicate_key.snapshot());

    for (unsigned fault = 0; fault < 9; ++fault) {
        auto view = valid.snapshot();
        switch (fault) {
        case 0: view.mask = 15; break;
        case 1: ++view.available; break;
        case 2: view.lastFree = view.capacity; break;
        case 3: view.keyCount = view.existingCount; break;
        case 4: view.capacity = 3; break;
        case 5: view.entries = nullptr; break;
        case 6: view.keys = nullptr; break;
        case 7: view.existingCount = 256; view.keyCount = 257; break;
        case 8: view.capacity = 131072; break;
        }
        reject(valid, view);
    }
}

void archive_output_aliases_and_full_capacity_fail_without_committing() {
    auto fixture = archive_fixture(8, {{0, 1, 1}, {8, 2, 1}, {3, 3, 1}, {16, 4, 1}});
    fixture.entries[0].next = 0;
    const auto before_entries = fixture.entries;
    const auto before_keys = fixture.keys;
    CHECK(archive::BuildRepair(fixture.snapshot(), fixture.entries.data(), fixture.entries.size()).status ==
          archive::BuildStatus::AliasedOutput);
    CHECK(archive::BuildRepair(fixture.snapshot(), fixture.entries.data() + 1, fixture.entries.size()).status ==
          archive::BuildStatus::AliasedOutput);
    CHECK(archive::BuildRepair(fixture.snapshot(), reinterpret_cast<archive::Entry*>(fixture.keys.data()),
                              fixture.entries.size()).status == archive::BuildStatus::AliasedOutput);
    CHECK(same_entries(fixture.entries, before_entries));
    CHECK(same_keys(fixture.keys, before_keys));

    std::vector<archive::Entry> staged(8, archive::Entry{0x1234, 0x4321});
    const auto before_staged = staged;
    CHECK(archive::BuildRepair(fixture.snapshot(), staged.data(), 7).status ==
          archive::BuildStatus::OutputSizeMismatch);
    CHECK(archive::BuildRepair(fixture.snapshot(), nullptr, staged.size()).status ==
          archive::BuildStatus::OutputSizeMismatch);
    CHECK(same_entries(staged, before_staged));

    auto full = archive_fixture(2, {{0, 1, 1}, {1, 2, 1}, {2, 3, 1}});
    full.entries[0].next = 0;
    const auto before_full = full.entries;
    std::vector<archive::Entry> full_output(2, archive::Entry{0x1234, 0x4321});
    const auto before_full_output = full_output;
    CHECK(archive::BuildRepair(full.snapshot(), full_output.data(), full_output.size()).status ==
          archive::BuildStatus::InsufficientCapacity);
    CHECK(same_entries(full.entries, before_full));
    CHECK(same_entries(full_output, before_full_output));
}

void archive_sentinel_is_never_an_overflow_link() {
    auto fixture = archive_fixture(65536, {{2, 1, 1}, {65538, 2, 1}});
    fixture.cursor = 0;  // Native collision allocation would select 0xFFFF next.
    const auto rebuilt = rebuild_and_verify(fixture);
    CHECK(rebuilt[kEnd].index == kEnd);
    CHECK(rebuilt[kEnd].next == kEnd);
    CHECK(rebuilt[2].next != kEnd);

    // A real home bucket of 0xFFFF is representable; only references *to* that
    // slot as an overflow node conflict with the next-link sentinel.
    auto home_at_sentinel = archive_fixture(65536,
        {{0xFFFF, 1, 1}, {0x1FFFF, 2, 1}, {0x2FFFF, 3, 1}});
    home_at_sentinel.entries[kEnd].next = kEnd;  // Disconnect the physical second member.
    rebuild_and_verify(home_at_sentinel);

    // Exact failure shape: incoming bucket 2 contains a displaced member of
    // bucket 0, but bucket 0's chain has lost its link to slot 2. Native insert
    // would chase 0xFFFF indefinitely while searching for that predecessor.
    auto broken_predecessor = archive_fixture(65536,
        {{0, 1, 1}, {65536, 2, 1}, {1, 3, 1}, {2, 4, 1}});
    CHECK(broken_predecessor.entries[2].index == 1);
    broken_predecessor.entries[0].next = kEnd;
    CHECK(lookup_archive(broken_predecessor.entries, broken_predecessor.keys,
                         broken_predecessor.keys[1]) == -1);
    rebuild_and_verify(broken_predecessor);
}

void archive_rebuild_properties_hold_across_varied_keys_and_layouts() {
    std::uint32_t state = 0x63A19B7DU;
    auto random = [&] {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    };
    for (unsigned trial = 0; trial < 600; ++trial) {
        const std::uint32_t capacity = 1U << (3 + random() % 7);
        const std::uint32_t count = 1 + random() % (std::min(capacity, 256U) - 1);
        std::vector<archive::Key> keys;
        for (std::uint32_t member = 0; member <= count; ++member) {
            // Half of cases deliberately concentrate every hash into one home.
            const std::uint32_t hash = trial % 2 ? random() : (random() & ~(capacity - 1));
            keys.push_back({hash, member, trial + 1});
        }
        auto fixture = archive_fixture(capacity, std::move(keys));
        assert_archive_members(fixture.entries, fixture.keys, fixture.existing);
        CHECK(archive::Analyze(fixture.snapshot()) == archive::Validation::Healthy);
        const auto head = fixture.keys.front().word0 & (capacity - 1);
        fixture.entries[head].next = static_cast<std::uint16_t>(head);
        rebuild_and_verify(fixture);
    }
}

}  // namespace

int main() {
    struct Test { const char* name; void (*run)(); };
    const Test tests[]{
        {"elapsed time", elapsed_time_is_bounded},
        {"stale-token revalidation", stale_tokens_cannot_change_reused_slots},
        {"recursion and capacity exhaustion", recursive_waits_and_exhaustion_preserve_active_records},
        {"thread-hash collisions", legacy_hash_collisions_keep_both_threads},
        {"one report per invocation", reporting_is_once_per_invocation_under_contention},
        {"concurrent snapshot consistency", concurrent_snapshots_never_mix_invocations},
        {"required address targets", address_library_requires_both_actual_targets},
        {"address mapping integrity", address_library_rejects_ambiguous_or_wrong_mappings},
        {"address input bounds", address_library_rejects_incomplete_and_oversized_files},
        {"code signature and range checks", code_ranges_and_loop_signatures_fail_closed},
        {"installation failure rollback", installation_orders_resources_and_rolls_back_each_failure},
        {"cleanup failures preserve live resources", failed_cleanup_preserves_live_trampoline_resources},
        {"healthy archive table preservation", healthy_archive_tables_are_untouched},
        {"archive topology repairs preserve members", archive_cycles_and_disconnected_chains_preserve_every_member},
        {"invalid archive input rejection", rejected_archive_inputs_never_change_source_or_output},
        {"archive alias and capacity rejection", archive_output_aliases_and_full_capacity_fail_without_committing},
        {"archive sentinel boundary", archive_sentinel_is_never_an_overflow_link},
        {"archive lookup properties", archive_rebuild_properties_hold_across_varied_keys_and_layouts},
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
    if (failures != 0) {
        std::cerr << failures << " test group(s) failed\n";
        return 1;
    }
    std::cout << "All " << (sizeof(tests) / sizeof(tests[0])) << " test groups passed\n";
    return 0;
}
