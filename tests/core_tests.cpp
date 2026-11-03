#include "address_library.h"
#include "archive_index.h"
#include "detour_contract.h"
#include "install_lifecycle.h"
#include "monitor_core.h"
#include "runtime_profile.h"
#include "detour_fixtures.h"
#include "native_patch.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
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

namespace detour = freezefix::detour;

std::vector<std::uint8_t> relative_jump(std::uintptr_t from, std::uintptr_t to) {
    CHECK(from <= static_cast<std::uintptr_t>(INT64_MAX));
    CHECK(to <= static_cast<std::uintptr_t>(INT64_MAX));
    const auto distance = static_cast<std::int64_t>(to) - static_cast<std::int64_t>(from) - 5;
    CHECK(distance >= INT32_MIN && distance <= INT32_MAX);
    const auto displacement = static_cast<std::int32_t>(distance);
    std::vector<std::uint8_t> result{0xE9, 0, 0, 0, 0};
    std::memcpy(result.data() + 1, &displacement, sizeof(displacement));
    return result;
}

struct DetourMemory {
    struct Region {
        std::uintptr_t address;
        std::vector<std::uint8_t> bytes;
        bool executable = true;
    };
    std::vector<Region> regions;
    std::vector<std::uintptr_t> module_entries;
    std::size_t largest_read = 0;

    bool read(std::uintptr_t address, void* output, std::size_t length, detour::ReadKind kind) {
        largest_read = std::max(largest_read, length);
        for (const auto& region : regions) {
            if (address < region.address || address - region.address > region.bytes.size()) continue;
            const auto offset = static_cast<std::size_t>(address - region.address);
            if (length > region.bytes.size() - offset ||
                (kind == detour::ReadKind::Code && !region.executable)) continue;
            std::memcpy(output, region.bytes.data() + offset, length);
            return true;
        }
        return false;
    }

    detour::Resolution resolve(std::uintptr_t start, std::uintptr_t continuation = 0x1000,
                               detour::StubKind kind = detour::StubKind::None) {
        return detour::Resolve(start, continuation, kind,
            [&](std::uintptr_t address, void* output, std::size_t length, detour::ReadKind read_kind) {
                return read(address, output, length, read_kind);
            },
            [&](std::uintptr_t address) {
                return std::find(module_entries.begin(), module_entries.end(), address) != module_entries.end();
            });
    }
};

void detour_windows_require_exact_native_tails_and_bounded_targets() {
    constexpr std::uintptr_t base = 0x10000;
    constexpr std::uintptr_t target = 0x90000;
    for (const auto& site : detour_test::Sites()) {
        const auto& window = site.window;
        const freezefix::CodeIdentity* profile = nullptr;
        for (const auto& identity : freezefix::kCodeIdentities)
            if (std::strcmp(identity.name, site.routine) == 0) profile = &identity;
        CHECK(profile != nullptr);
        CHECK(profile->length == site.routine_length);
        CHECK(profile->window_count == (std::strcmp(site.routine, "archive_add") == 0 ? 3U : 1U));
        bool exact_profile_window = false;
        for (std::size_t i = 0; i < profile->window_count; ++i) {
            const auto& actual = profile->windows[i];
            if (actual.offset == window.offset && actual.length == window.length &&
                actual.original == window.original && actual.stub == window.stub) exact_profile_window = true;
        }
        CHECK(exact_profile_window);
        std::vector<std::uint8_t> native(site.routine_length, 0xCC);
        std::copy_n(window.original.begin(), window.length, native.begin() + window.offset);
        CHECK(detour::ParseWindow(native.data(), native.size(), base, window).state ==
              detour::WindowState::Native);

        // Real Daytripper fills the whole overwritten span with NOPs. A branch
        // writer that leaves part or all of the original tail is also explicit
        // in the accepted contract; unrelated padding is never ignored.
        for (std::size_t padding = 0; padding <= window.length - 5; ++padding) {
            auto patched = native;
            const auto branch = relative_jump(base + window.offset, target);
            std::copy(branch.begin(), branch.end(), patched.begin() + window.offset);
            std::fill_n(patched.begin() + window.offset + 5, padding, std::uint8_t{0x90});
            const auto parsed = detour::ParseWindow(patched.data(), patched.size(), base, window);
            CHECK(parsed.state == detour::WindowState::Detoured);
            CHECK(parsed.target == target);
            CHECK(parsed.continuation == base + window.offset + window.length);
            auto normalized = patched;
            CHECK(detour::NormalizePatch(normalized.data(), normalized.size(), window));
            CHECK(normalized == native);
        }

        auto patched = native;
        const auto branch = relative_jump(base + window.offset, target);
        std::copy(branch.begin(), branch.end(), patched.begin() + window.offset);
        for (unsigned fault = 0; fault < 4; ++fault) {
            auto invalid = patched;
            if (fault == 0) invalid[window.offset] = 0xE8; // A call is not this detour contract.
            if (fault == 1) invalid[window.offset + 5] = 0xCC;
            if (fault == 2) invalid[window.offset + window.length - 1] ^= 1;
            if (fault == 3) {
                invalid[window.offset + 5] = 0x90;
                invalid[window.offset + 7] = 0x90; // A NOP after an untouched tail is not padding.
            }
            CHECK(detour::ParseWindow(invalid.data(), invalid.size(), base, window).state ==
                  detour::WindowState::Rejected);
        }
        CHECK(detour::ParseWindow(patched.data(), window.offset + window.length - 1,
                                  base, window).state == detour::WindowState::Rejected);
        CHECK(!detour::NormalizePatch(patched.data(), window.offset + window.length - 1, window));
        CHECK(detour::ParseWindow(nullptr, native.size(), base, window).state ==
              detour::WindowState::Rejected);
        CHECK(!detour::NormalizePatch(nullptr, native.size(), window));
        auto invalid_window = window;
        invalid_window.offset = SIZE_MAX;
        CHECK(detour::ParseWindow(patched.data(), patched.size(), base, invalid_window).state ==
              detour::WindowState::Rejected);
        invalid_window = window;
        invalid_window.length = window.original.size() + 1;
        CHECK(detour::ParseWindow(patched.data(), patched.size(), base, invalid_window).state ==
              detour::WindowState::Rejected);
        invalid_window.length = 4;
        CHECK(detour::ParseWindow(patched.data(), patched.size(), base, invalid_window).state ==
              detour::WindowState::Rejected);
    }

    std::uintptr_t resolved = 0;
    CHECK(detour::CheckedRelativeTarget(100, 5, 20, resolved) && resolved == 125);
    CHECK(detour::CheckedRelativeTarget(100, 5, -25, resolved) && resolved == 80);
    CHECK(!detour::CheckedRelativeTarget(UINTPTR_MAX - 2, 5, 0, resolved));
    CHECK(!detour::CheckedRelativeTarget(UINTPTR_MAX - 5, 5, 1, resolved));
    CHECK(!detour::CheckedRelativeTarget(10, 5, -16, resolved));
    CHECK(!detour::CheckedRelativeTarget(10, 5, INT64_MIN, resolved));
}

void detour_relays_are_bounded_and_must_reach_a_module() {
    constexpr std::uintptr_t endpoint = 0x9000;
    DetourMemory memory;
    memory.module_entries.push_back(endpoint);
    memory.regions.push_back({endpoint, std::vector<std::uint8_t>(128, 0xCC)});
    CHECK(memory.resolve(endpoint).accepted);

    memory.regions.push_back({0x4000, relative_jump(0x4000, 0x3000)});
    memory.regions.push_back({0x3000, relative_jump(0x3000, endpoint)});
    const auto chain = memory.resolve(0x4000);
    CHECK(chain.accepted && chain.endpoint == endpoint);
    CHECK(memory.largest_read <= 128);

    // RIP-relative indirect relay with its address cell separate from code.
    const std::int32_t cell_displacement = 0x100;
    std::vector<std::uint8_t> indirect{0xFF, 0x25, 0, 0, 0, 0};
    std::memcpy(indirect.data() + 2, &cell_displacement, sizeof(cell_displacement));
    std::vector<std::uint8_t> cell(sizeof(std::uint64_t));
    const std::uint64_t endpoint64 = endpoint;
    std::memcpy(cell.data(), &endpoint64, sizeof(endpoint64));
    memory.regions.push_back({0x5000, indirect});
    memory.regions.push_back({0x5106, cell, false});
    CHECK(memory.resolve(0x5000).accepted);
    memory.regions.back().bytes.resize(7);
    CHECK(!memory.resolve(0x5000).accepted);
    memory.regions.back().bytes = cell;
    memory.regions[memory.regions.size() - 2].executable = false;
    CHECK(!memory.resolve(0x5000).accepted);

    std::vector<std::uint8_t> absolute{0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0};
    std::memcpy(absolute.data() + 2, &endpoint64, sizeof(endpoint64));
    memory.regions.push_back({0x5800, absolute});
    CHECK(memory.resolve(0x5800).accepted);
    memory.regions.back().bytes.back() = 0xD0; // Calling through RAX is not a jump relay.
    CHECK(!memory.resolve(0x5800).accepted);

    memory.regions.push_back({0x6000, relative_jump(0x6000, 0x6000)});
    CHECK(!memory.resolve(0x6000).accepted);
    memory.regions.push_back({0x6100, relative_jump(0x6100, 0x6200)});
    memory.regions.push_back({0x6200, relative_jump(0x6200, 0x6100)});
    CHECK(!memory.resolve(0x6100).accepted);
    memory.regions.push_back({0x7000, std::vector<std::uint8_t>(128, 0x90)});
    CHECK(!memory.resolve(0x7000).accepted); // Readable executable anonymous memory is not an endpoint.
    CHECK(!memory.resolve(0).accepted);
    CHECK(!memory.resolve(0xDEADBEEF).accepted);
    memory.regions.push_back({0x8000, {0xE9, 0, 0, 0}});
    CHECK(!memory.resolve(0x8000).accepted); // Truncated displacement.

    DetourMemory deep;
    deep.module_entries.push_back(endpoint);
    deep.regions.push_back({endpoint, std::vector<std::uint8_t>(128, 0xCC)});
    for (std::size_t index = 0; index <= detour::kMaxHops; ++index) {
        const std::uintptr_t current = 0x10000 + index * 0x100;
        const auto next = index == detour::kMaxHops ? endpoint : current + 0x100;
        deep.regions.push_back({current, relative_jump(current, next)});
    }
    CHECK(!deep.resolve(0x10000).accepted);
}

void source_verified_daytripper_stubs_require_every_fixed_byte_and_return() {
    constexpr std::uintptr_t start = 0x4000;
    constexpr std::uintptr_t helper = 0x9000;
    constexpr std::uintptr_t continuation = 0x12345678;
    for (const auto& site : detour_test::Sites()) {
        const auto native_stub = detour_test::Stub(site, helper, continuation);
        DetourMemory memory;
        memory.module_entries.push_back(helper);
        memory.regions.push_back({helper, std::vector<std::uint8_t>(128, 0xCC)});
        memory.regions.push_back({start, native_stub});
        const auto resolved = memory.resolve(start, continuation, site.window.stub);
        CHECK(resolved.accepted && resolved.endpoint == helper);
        CHECK(memory.largest_read <= 128);

        for (std::size_t byte = 0; byte < native_stub.size(); ++byte) {
            if ((byte >= site.helper_offset && byte < site.helper_offset + 8) ||
                (byte >= site.return_offset && byte < site.return_offset + 8)) continue;
            memory.regions.back().bytes = native_stub;
            memory.regions.back().bytes[byte] ^= 1;
            CHECK(!memory.resolve(start, continuation, site.window.stub).accepted);
        }
        memory.regions.back().bytes = detour_test::Stub(site, helper, continuation + 1);
        CHECK(!memory.resolve(start, continuation, site.window.stub).accepted);
        memory.regions.back().bytes = detour_test::Stub(site, 0xA000, continuation);
        memory.regions.push_back({0xA000, std::vector<std::uint8_t>(128, 0x90)});
        CHECK(!memory.resolve(start, continuation, site.window.stub).accepted);
        memory.regions.pop_back();
        memory.regions.back().bytes = native_stub;
        CHECK(!memory.resolve(start, continuation, detour::StubKind::None).accepted);
        const auto other_kind = site.window.stub == detour::StubKind::LookupName
            ? detour::StubKind::AddArchive : detour::StubKind::LookupName;
        CHECK(!memory.resolve(start, continuation, other_kind).accepted);
        memory.regions.back().bytes.pop_back();
        CHECK(!memory.resolve(start, continuation, site.window.stub).accepted);

        // A helper may be reached through ordinary relays. A second call-and-
        // return stub would jump back to the game from inside the helper call,
        // breaking the outer stub's return/stack contract, so reject it.
        constexpr std::uintptr_t helper_relay = 0xA000;
        memory.regions.back().bytes = detour_test::Stub(site, helper_relay, continuation);
        memory.regions.push_back({helper_relay, relative_jump(helper_relay, helper)});
        CHECK(memory.resolve(start, continuation, site.window.stub).accepted);
        memory.regions.back().bytes = detour_test::Stub(site, helper, continuation);
        CHECK(!memory.resolve(start, continuation, site.window.stub).accepted);
    }
}

void diagnostic_crc_locates_the_first_changed_byte() {
    const std::vector<std::uint8_t> bytes{'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    // Independent standard zlib CRC32 vector and each prefix's finalized CRC.
    const std::array<std::uint32_t, 9> prefix{{0x83DCEFB7U, 0x4F5344CDU, 0x884863D2U,
        0x9BE3E0A3U, 0xCBF53A1CU, 0x0972D361U, 0x5003699FU, 0x9AE0DAAFU, 0xCBF43926U}};
    std::uint32_t crc = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        crc = detour::Crc32Step(crc, bytes[i]);
        CHECK(crc == prefix[i]);
    }
    CHECK(detour::FirstDifference(bytes.data(), bytes.size(), prefix.data(), prefix.size()) ==
          detour::kNoDifference);
    for (std::size_t first = 0; first < bytes.size(); ++first) {
        auto changed = bytes;
        changed[first] ^= 0x40;
        if (first + 1 < changed.size()) changed.back() ^= 0x20;
        CHECK(detour::FirstDifference(changed.data(), changed.size(), prefix.data(), prefix.size()) == first);
    }
    CHECK(detour::FirstDifference(nullptr, bytes.size(), prefix.data(), prefix.size()) ==
          detour::kNoDifference);
    CHECK(detour::FirstDifference(bytes.data(), bytes.size(), nullptr, prefix.size()) ==
          detour::kNoDifference);
    CHECK(detour::FirstDifference(bytes.data(), bytes.size() - 1, prefix.data(), prefix.size()) ==
          detour::kNoDifference);
}

}  // namespace

// 601 keys spanning the native/extended boundary. The rebuild model is
// storage-agnostic - it receives one contiguous key array - so the boundary is
// a numbering fact here; what matters is that collision chains cross it.
void extended_archive_rebuild_supports_601_keys() {
    constexpr std::uint32_t kCapacity = 65536;
    constexpr std::uint32_t kLast = 600;  // 601 existing members, indices 0..600
    std::vector<archive::Key> keys;
    keys.reserve(kLast + 2);
    // Four homes, so every chain is ~150 members long and each one crosses the
    // 255 boundary in both directions.
    for (std::uint32_t index = 0; index <= kLast + 1; ++index) {
        const std::uint32_t group = index % 4;
        keys.push_back({group * 0x1000u, index + 1u, 0x5A5A0000u + group});
    }
    auto fixture = archive_fixture(kCapacity, keys);
    CHECK(fixture.existing == kLast + 1);
    const std::uint32_t boundaries[] = {0, 1, 254, 255, 256, 286, 511, 512, 592, 599, 600};
    for (std::uint32_t boundary : boundaries) {
        CHECK(lookup_archive(fixture.entries, fixture.keys, keys[boundary]) ==
              static_cast<int>(boundary));
    }
    // Break one chain: membership stays complete, topology does not.
    fixture.entries[0].next = kEnd;
    const auto rebuilt = rebuild_and_verify(fixture);
    for (std::uint32_t boundary : boundaries) {
        CHECK(lookup_archive(rebuilt, fixture.keys, keys[boundary]) ==
              static_cast<int>(boundary));
    }
    CHECK(lookup_archive(rebuilt, fixture.keys, archive::Key{0, 0xFFFFFFFF, 0xFFFFFFFF}) == -1);
}

// 1000 deterministic cases above 500 members, each with a broken chain. Seeds
// are fixed so a failure is reproducible from the trial index alone.
void extended_archive_generated_cases_hold_above_500_keys() {
    std::uint32_t state = 0x9E3779B9u;
    auto random = [&] {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    };
    constexpr std::uint32_t kCapacity = 65536;
    unsigned cases = 0;
    for (unsigned trial = 0; trial < 1000; ++trial) {
        const std::uint32_t count = 500 + random() % 102;  // 500..601 existing members
        const std::uint32_t homes = 1 + random() % 8;
        std::vector<archive::Key> keys;
        keys.reserve(count + 2);
        for (std::uint32_t index = 0; index <= count + 1; ++index) {
            const std::uint32_t home = (random() % homes) * 0x1000u;
            keys.push_back({home, index + 1u, trial + 1u});
        }
        auto fixture = archive_fixture(kCapacity, keys);
        CHECK(fixture.existing == count + 1);
        const std::uint32_t victim = random() % (count + 1);
        fixture.entries[keys[victim].word0 & (kCapacity - 1)].next = kEnd;
        rebuild_and_verify(fixture);
        ++cases;
    }
    CHECK(cases == 1000);
}

// The correction stubs are emitted as bytes, so pin their exact encoding. A
// refactor that changes a register or an offset must fail here rather than in
// the game.
void native_correction_stubs_keep_their_verified_encoding() {
    constexpr std::uintptr_t kHelper = 0x1122334455667788ull;
    const std::vector<std::uint8_t> lookup = freezefix::native::BuildLookupStub(kHelper);
    const std::vector<std::uint8_t> expectedLookup{
        0x50, 0x51, 0x52,
        0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
        0x48, 0x83, 0xEC, 0x20,
        0x49, 0x8D, 0x8B, 0x30, 0x10, 0x00, 0x00,
        0x44, 0x89, 0xCA,
        0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x20,
        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,
        0x5A, 0x59,
        0x4C, 0x8D, 0x80, 0xD0, 0xEF, 0xFF, 0xFF,
        0x58, 0xC3};
    CHECK(lookup == expectedLookup);

    auto contains = [](const std::vector<std::uint8_t>& code,
                       std::initializer_list<std::uint8_t> needle) {
        return std::search(code.begin(), code.end(), needle.begin(), needle.end()) != code.end();
    };

    const std::vector<std::uint8_t> incoming = freezefix::native::BuildIncomingStub(kHelper);
    CHECK(incoming.size() == 54);
    CHECK(contains(incoming, {0x48, 0x89, 0xC1}));  // mov rcx, rax
    CHECK(contains(incoming, {0x44, 0x89, 0xDA}));  // mov edx, r11d
    CHECK(contains(incoming, {0x8B, 0x18}));        // mov ebx, [rax]
    CHECK(contains(incoming, {0x4D, 0x89, 0xC6}));  // mov r14, r8
    CHECK(incoming[52] == 0x58 && incoming[53] == 0xC3);  // pop rax; ret

    const std::vector<std::uint8_t> displaced = freezefix::native::BuildDisplacedStub(kHelper);
    CHECK(displaced.size() == 57);
    CHECK(contains(displaced, {0x48, 0x89, 0xC1}));        // mov rcx, rax
    CHECK(contains(displaced, {0x89, 0xF2}));              // mov edx, esi
    CHECK(contains(displaced, {0xC1, 0xEA, 0x10}));        // shr edx, 16
    CHECK(contains(displaced, {0x44, 0x8B, 0x08}));        // mov r9d, [rax]
    CHECK(contains(displaced, {0x44, 0x23, 0xCF}));        // and r9d, edi (REX.R)
    CHECK(displaced[55] == 0x58 && displaced[56] == 0xC3); // pop rax; ret

    CHECK(freezefix::native::kLookupLoopOriginal.size() == 8);
    CHECK(freezefix::native::kInsertIncomingOriginal.size() == 7);
    CHECK(freezefix::native::kInsertDisplacedOriginal.size() == 7);
}

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
        {"detour window bounds and native tails", detour_windows_require_exact_native_tails_and_bounded_targets},
        {"detour relay and module validation", detour_relays_are_bounded_and_must_reach_a_module},
        {"verified Daytripper stub contracts", source_verified_daytripper_stubs_require_every_fixed_byte_and_return},
        {"first-difference CRC diagnostics", diagnostic_crc_locates_the_first_changed_byte},
    {"extended archive rebuild at 601 keys", extended_archive_rebuild_supports_601_keys},
    {"extended archive generated cases above 500 keys", extended_archive_generated_cases_hold_above_500_keys},
    {"native correction stub encoding", native_correction_stubs_keep_their_verified_encoding},
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
