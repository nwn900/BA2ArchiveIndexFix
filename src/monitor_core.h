#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace freezefix {

// A token identifies one invocation, not a thread. Recursive calls therefore
// receive separate records, and a late end/report cannot affect a reused slot.
struct Token {
    std::size_t slot = (std::numeric_limits<std::size_t>::max)();
    std::uint64_t generation = 0;

    explicit constexpr operator bool() const noexcept {
        return slot != (std::numeric_limits<std::size_t>::max)();
    }
};

struct Snapshot {
    Token token{};
    std::uint32_t thread_id = 0;
    std::uintptr_t object = 0;
    std::uint64_t since_ms = 0;
    bool reported = false;
};

// The watchdog's clock sample may predate an invocation that starts while the
// slots are being scanned. Such a call has no elapsed time in that sample.
constexpr std::uint64_t elapsed_ms(std::uint64_t now, std::uint64_t since) noexcept {
    return now >= since ? now - since : 0;
}

// Bounded, allocation-free diagnostic tracking. No slot lock remains held while
// the caller executes engine code. A full registry simply declines a new record.
//
// Snapshots are coherent observations, not lifetime guards: the invocation can
// finish immediately afterward. Never dereference Snapshot::object or use an
// observation as authority to alter an engine lock, table, or thread.
template <std::size_t Capacity>
class MonitorCore {
    static_assert(Capacity > 0, "A monitor needs at least one slot");
    static_assert(Capacity <= (std::numeric_limits<std::uint32_t>::max)(),
                  "Capacity must fit the bounded hash reduction");
    static_assert(std::atomic<std::uint32_t>::is_always_lock_free,
                  "Hook tracking requires lock-free 32-bit atomics");
    static_assert(std::atomic<std::uintptr_t>::is_always_lock_free,
                  "Hook tracking requires lock-free pointer-sized atomics");
    static_assert(std::atomic<std::uint64_t>::is_always_lock_free,
                  "Hook tracking requires lock-free 64-bit atomics");

    // The low two bits encode free / writing / active / active-and-reported.
    // Finishing an invocation advances the generation by four. Reporting is a
    // state transition in this same atomic, so a stale report cannot mark a new
    // invocation. Generations never wrap: an exhausted slot is left unavailable.
    static constexpr std::uint64_t kMask = 3;
    static constexpr std::uint64_t kFree = 0;
    static constexpr std::uint64_t kWriting = 1;
    static constexpr std::uint64_t kActive = 2;
    static constexpr std::uint64_t kReported = 3;
    static constexpr std::uint64_t kStep = 4;
    static constexpr std::uint64_t kMaxGeneration =
        (std::numeric_limits<std::uint64_t>::max)() - kStep;

    struct Slot {
        std::atomic<std::uint64_t> state{0};
        std::atomic<std::uint32_t> thread_id{0};
        std::atomic<std::uintptr_t> object{0};
        std::atomic<std::uint64_t> since_ms{0};
    };

    std::array<Slot, Capacity> slots_{};

    static constexpr bool active_state(std::uint64_t state) noexcept {
        return (state & kMask) == kActive || (state & kMask) == kReported;
    }

    static constexpr bool valid_token(const Token& token) noexcept {
        return token.slot < Capacity && (token.generation & kMask) == 0 &&
               token.generation <= kMaxGeneration;
    }

public:
    MonitorCore() noexcept = default;
    MonitorCore(const MonitorCore&) = delete;
    MonitorCore& operator=(const MonitorCore&) = delete;

    static constexpr std::size_t capacity() noexcept { return Capacity; }

    Token begin(std::uint32_t thread_id, std::uintptr_t object,
                std::uint64_t since_ms) noexcept {
        const std::uint32_t mixed = thread_id * 2654435761u;
        std::size_t index = static_cast<std::size_t>(
            (static_cast<std::uint64_t>(mixed) * Capacity) >> 32);

        // One attempt per slot, with no retry loop on a contended slot. The
        // common case is one hash lookup; collisions probe other free records.
        for (std::size_t attempt = 0; attempt < Capacity; ++attempt) {
            Slot& slot = slots_[index];
            std::uint64_t state = slot.state.load(std::memory_order_acquire);
            if ((state & kMask) == kFree && state <= kMaxGeneration &&
                slot.state.compare_exchange_strong(state, state | kWriting,
                                                   std::memory_order_acq_rel,
                                                   std::memory_order_acquire)) {
                const std::uint64_t generation = state;
                slot.thread_id.store(thread_id, std::memory_order_release);
                slot.object.store(object, std::memory_order_release);
                slot.since_ms.store(since_ms, std::memory_order_release);
                slot.state.store(generation | kActive, std::memory_order_release);
                return Token{index, generation};
            }
            if (++index == Capacity) index = 0;
        }
        return {};
    }

    bool end(const Token& token) noexcept {
        if (!valid_token(token)) return false;
        Slot& slot = slots_[token.slot];
        std::uint64_t expected = token.generation | kActive;
        const std::uint64_t next = token.generation + kStep;
        if (slot.state.compare_exchange_strong(expected, next,
                                               std::memory_order_acq_rel,
                                               std::memory_order_acquire)) {
            return true;
        }
        // A watchdog may have marked this invocation between publication and
        // return. There is only one such transition, so at most one retry is
        // needed. A different generation is never changed.
        if (expected != (token.generation | kReported)) return false;
        return slot.state.compare_exchange_strong(expected, next,
                                                  std::memory_order_acq_rel,
                                                  std::memory_order_acquire);
    }

    bool try_snapshot(std::size_t index, Snapshot& out) const noexcept {
        if (index >= Capacity) return false;
        const Slot& slot = slots_[index];
        const std::uint64_t before = slot.state.load(std::memory_order_acquire);
        if (!active_state(before)) return false;

        Snapshot result{};
        result.token = Token{index, before & ~kMask};
        // Acquire/release applies to the payload too. If any load observes a
        // later invocation's field, its preceding reservation happens before
        // the final state load, which must then reject the old generation.
        result.thread_id = slot.thread_id.load(std::memory_order_acquire);
        result.object = slot.object.load(std::memory_order_acquire);
        result.since_ms = slot.since_ms.load(std::memory_order_acquire);
        const std::uint64_t after = slot.state.load(std::memory_order_acquire);
        if (!active_state(after) || (after & ~kMask) != result.token.generation) {
            return false;
        }
        result.reported = (after & kMask) == kReported;
        out = result;
        return true;
    }

    bool is_active(const Token& token) const noexcept {
        if (!valid_token(token)) return false;
        const std::uint64_t state = slots_[token.slot].state.load(std::memory_order_acquire);
        return active_state(state) && (state & ~kMask) == token.generation;
    }

    // At most one report per invocation. Both a repeated report and a report
    // using a stale token fail without changing any record.
    bool try_mark_reported(const Token& token) noexcept {
        if (!valid_token(token)) return false;
        std::uint64_t expected = token.generation | kActive;
        return slots_[token.slot].state.compare_exchange_strong(
            expected, token.generation | kReported,
            std::memory_order_acq_rel, std::memory_order_acquire);
    }
};

}  // namespace freezefix
