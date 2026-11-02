# Archive index engine contract

This document describes the narrow native contract used by FreezeFixF4 2.0. It is
an implementation specification tied to one executable profile, not a claim that
every archive-index failure has the same cause or can be repaired safely.

The source of truth for constants is [runtime_profile.h](../src/runtime_profile.h).
The pure transformation is in [archive_index.h](../src/archive_index.h); the
Windows adapter and hook guards are in [main.cpp](../src/main.cpp).

## 1. Reference image and code identity

The analysis used an unpacked x64 executable with these properties:

| Property | Value |
|---|---|
| Reference file | `Fallout4.exe.unpacked.exe` |
| File version from the PE version resource | `1.10.163.0` |
| File size | 65,319,936 bytes |
| Preferred image base | `0x140000000` |
| PE timestamp field | `1574715642` |
| File SHA-256 | `9a147a35686691ac6c52c2b3bc24027fc26119c2eb77716e10900af29a61609e` |

The full-file hash identifies the research input. It is **not** a requirement
that a player's Steam-wrapped executable have the same on-disk file hash.
Runtime validation hashes the following complete, loaded routine ranges before
installing hooks. Addresses below are relative virtual addresses, independent of
the actual ASLR load address. Lengths are hexadecimal byte counts.

| Profile name | RVA | Length | SHA-256 |
|---|---|---|---|
| `archive_insert` | `0x1B772F0` | `0x16A` | `4810170d9d4caaf6ce750980168bbcf25d30a8eb73a9c772f2810d15007479f3` |
| `archive_add` | `0x1B767F0` | `0xF7` | `5afbd973246d22bb750016b092c2df7922e36d704936494d274d416e3da1d156` |
| `archive_lookup` | `0x1B78AF0` | `0xFE` | `f4172a68a14be8e48a1117fc70c1200f78623827f0ae64826742d890a6409895` |
| `archive_owner` | `0x1B7A2B0` | `0x111` | `7c2af2fa901db3122f7a16b3d892ef39957a0e7e42351d2d3dd56d2e2a8db593` |
| `lock_read` | `0x1B10930` | `0x70` | `a19c0521fe77c05a85d2541aa082b345884b5310f9890d23052e4cae062e2b8c` |

The `lock_read` check and hook are required only when `MonitorLockWaits=1`.
The other profile checks apply before installation. The Address Library must
also map ID `1541972` to `0x1B772F0` and ID `1573164` to `0x1B10930`; it is parsed
with file-size, count, ordering, duplicate-ID, and exact-RVA checks.

An unreadable range, a range outside the loaded executable's readable executable
sections, or any identity mismatch prevents installation. The plugin does not
scan for a similar instruction sequence or chain an unknown existing patch.
These checks establish a known starting profile. Before each proposed commit,
the adapter compares the unchanged routines against the verified original bytes
and compares each hooked routine's body after the five-byte entry patch against
its original bytes. It separately checks its exact installed entry jump and
relay, whose destination was verified as the expected plugin callback. A changed
routine or hook makes the recovery attempt decline. These checks do not prevent
another plugin from racing a later code or data modification.

No proprietary executable or full routine extract is included here. The optional
[native validation harness](../tests/run_native_validation.py) accepts a locally
supplied reference image or exact routine extracts, verifies their hashes, and
executes the insertion and lookup leaf routines only against synthetic data.

## 2. Correct subsystem and native call contract

`archive_insert` is the `BaseInsert` operation of the small-index scatter table
used by `BSResource::Archive2::Index`. It indexes resource name IDs. The original
movie-definition-table description confused a blocked resource consumer with the
object being modified.

The reviewed writer path at `0x1B7A2B0` acquires the archive writer lock through
the call at `0x1B7A313`, calls `Archive2::Index::AddDataFile` at `0x1B7A346`, and
releases the lock through the call at `0x1B7A3A1`. Within `AddDataFile`, the first
insertion call returns to `0x1B768AC`. **Only this first call site is eligible for
recovery.** The retry after native growth returns to `0x1B768CE` and is left to
the original routine.

At the eligible insertion call, `AddDataFile` has prepared the incoming key at
external index `count`. The third argument is a reference to the start of the
fixed key array. The caller increments the count after a successful insertion.
The replacement therefore returns `true` only after a staged table includes all
old indices **and the incoming index**. Calling native insertion again after
that commit would be incorrect.

A false return from native insertion triggers native table growth and a retry.
The adapter does not synthesize `false` as a generic escape from a damaged state.
That would introduce an unverified growth path and would not establish the
correctness of the retry. On a declined repair, it calls the original function
with the original arguments.

## 3. Object and entry layout

Let `self` be the table pointer passed to `BaseInsert`. The containing
`Archive2::Index` begins at `self - 0x10` and has the reviewed extent `0x1C60`.

| Offset from `self` | Size | Meaning |
|---|---|---|
| `0x00` | 8 bytes | Allocator/opaque field; preserved |
| `0x08` | 8 bytes | Pointer to the slot array; preserved |
| `0x10` | 4 bytes | Capacity |
| `0x14` | 4 bytes | Mask, equal to capacity minus one |
| `0x18` | 4 bytes | Number of available slots |
| `0x1C` | 4 bytes | Last-free search cursor |
| `0x1020` | 256 × 12 bytes | Fixed resource name-ID array |
| `0x1C20` | 4 bytes | Existing name count |
| `0x1C48` | 8 bytes | Writer owner thread ID followed by lock state |

Each four-byte slot consists of a 16-bit `next` link followed by a 16-bit external
`index`. A completely empty slot has both halves equal to `0xFFFF`. A nonempty
slot's `index` selects one of the fixed twelve-byte IDs. A `next` value of
`0xFFFF` terminates a collision chain.

The reviewed constructor initializes the table with 512 slots. The model accepts
power-of-two capacities from 2 through 65,536, provided the remaining guards
hold, because those capacities fit the recovered link representation. The
256-element key array independently limits the pending external index to less
than 256. A large slot capacity does not authorize more payload keys.

The adapter requires the current thread to be the recorded owner and the lock
state to equal `0x80000001`. Recursive, absent, or different ownership is outside
the accepted contract. It also checks pointer arithmetic, readable snapshots,
writable destination ranges, and separation of the slot allocation from the
containing object and argument-reference storage.

## 4. Lookup, insertion, and the failure condition

Native lookup computes `home = key.word0 & mask`, reads the external index stored
at that slot, and compares all three 32-bit words of the selected key. On a miss
it follows the 16-bit links until `0xFFFF`. A successful lookup returns the
external index; a miss returns the current name count. Physical slot position is
not the returned identity.

Insertion uses an empty home directly. When a home is occupied, it searches
backwards from the free cursor for an empty slot. If the occupant belongs to the
same home, the new entry is added to that chain. If the occupant was displaced
from another home, insertion finds its predecessor, moves the occupant to the
free slot, updates the predecessor, and installs the new member at its own home.

The predecessor search assumes that the displaced member is reachable from its
original home. A broken chain violates that assumption. In the reported loop,
following an empty slot gives the sentinel value again and the predecessor walk
never reaches its target. Other malformed links can instead produce an invalid
read; a missing predecessor is not inherently a safe condition to skip.

The original plugin changed a link inferred from a suspended thread's registers.
That did not prove that the chosen entry was a valid predecessor or that every
member remained reachable. Its accepted instruction range also included code
where the register no longer held a slot index. Version 2 performs no such
register-based repair.

### The `0xFFFF` allocation edge

At capacity 65,536, physical slot `0xFFFF` exists, but the same numeric value is
reserved as the end-of-chain link. The slot can serve as a direct hash home; it
cannot be encoded as an overflow destination.

The native free-slot search can select that slot under a particular cursor and
occupancy state. In a synthetic table with capacity 65,536, cursor zero, and an
occupied incoming home, the original routine can return success after allocating
slot `0xFFFF` while lookup cannot reach the newly inserted key. The native-code
harness reproduces that conditional defect. It does **not** prove that this was
the source of the original player's damaged table, or that an otherwise pristine
game reaches that state.

The model simulates the next native free-slot choice. It requests a rebuild for
this specific hazard even if the current topology is otherwise valid. Its own
builder permits `0xFFFF` as a direct home and always excludes it from overflow
allocation.

## 5. When a rebuild is justified

The core takes a bounded snapshot containing the slot array, the existing keys,
the incoming key, count, capacity, mask, availability, and free cursor. It first
establishes that membership is authoritative enough to reconstruct topology:

- Capacity is a supported power of two, mask is capacity minus one, the free
  cursor is in range, and availability is exactly capacity minus existing count.
- The pending index equals the existing count and is below the 256-key limit.
  The supplied key count is exactly existing count plus one.
- Every old external index from zero through count minus one occurs exactly
  once. There are no missing, duplicate, foreign, or partially empty members.
- All complete twelve-byte keys, including the incoming key, are distinct.
  Duplicate keys are declined because their selection semantics are ambiguous.

With membership established, every existing member must be reachable from its
own hash home, every traversed member must belong to that home, and each chain
must terminate within the bounded membership count. Cycles, cross-links,
disconnected members, and invalid links can therefore be recognized as topology
failures while intact membership remains available for rebuilding.

A healthy topology with no prospective sentinel-allocation hazard is left to
native insertion. An invalid membership or metadata state is declined. A
topology failure with valid membership, or the specific sentinel hazard, is
eligible for staging.

## 6. Staging and publication

`BuildRepair` initializes a separate buffer of the same capacity and inserts
indices zero through the pending index in order. It follows the recovered native
collision and relocation rules with bounded searches and the sentinel exclusion.
It then verifies complete membership and terminating lookup chains in the
finished buffer. The source snapshot is immutable; an output buffer that aliases
the source slots or keys is rejected.

The resulting table may use different physical slots and chain order. It keeps
each twelve-byte key associated with the same external index. Because accepted
keys are unique and every index remains reachable from its hash home, the
reviewed lookup returns the same external indices for the old keys and the new
index for the incoming key. Native growth also relocates physical entries while
preserving external indices; the table slots are not the archive identity.

Before publication, the adapter captures the live state again and requires an
exact match of the header, keys, count, key-array reference, and all slots, with
current writer ownership still established. It then revalidates the code and
installed-hook contract described above and checks ownership once more. The
proposed changes are limited to
the existing slot array and its availability/free-cursor fields. Capacity, mask,
allocation pointer, key bytes, external index values, payload arrays, and lock
fields are preserved. The original caller performs its normal count increment.

Publication relies on the reviewed engine writer lock for exclusivity. Snapshot
comparison and memory-range checks are additional guards, not a replacement for
that lock and not proof against an unrelated plugin racing or corrupting memory.
There is no speculative live write followed by rollback. A C++ failure during
preparation declines before publication. An access violation during the final
copies is not caught and treated as a successful or recoverable repair; an
access fault or process failure during multi-byte publication cannot be made safe
merely by validating the input. Remaining runtime checks are recorded in
[validation.md](validation.md).

## 7. Declined and unsupported states

The adapter refuses recovery when profile identity, caller, ownership, bounds,
layout, count, membership, uniqueness, staging, or unchanged-snapshot checks fail.
It also refuses a rebuild that cannot fit the pending member in the existing
capacity. It does not grow an ambiguous table, infer a lost key, resolve duplicate
keys, reconstruct payload data, or alter the lock to let readers pass.

Declining recovery is a restriction on plugin writes. It does not make the
original engine function safe for a corrupted input. The native call still runs
and may hang or fail as before. A table already stuck inside insertion before the
hook is installed cannot be rescued by this entry detour.

The watchdog only drains bounded diagnostic events and optionally reports long
read-lock waits. It never rewrites game memory, changes lock fields, inspects a
suspended writer's register context, or parks a thread. MinHook's brief thread
suspension during ordinary hook installation is separate from this runtime
policy. The old watchdog thresholds and spin-sampling options are removed.

Hook installation also preserves callback lifetime on failure. If an enable
attempt fails after any hook has become callable, recovery remains inactive and
the pinned DLL, trampolines, and related resources remain resident until process
exit. A retained callback passes through to the original function. Removing its
trampoline without proving that all callbacks have finished could invalidate a
future call from an already-running callback, so that cleanup is deliberately
not attempted. Failures before any hook becomes callable can use normal cleanup.

## 8. Evidence and limits

At the time of this change, the portable suite contains 18 test groups, including
600 generated archive-index cases. The separate native-code harness passed 192
recovery cases and 34,858 checks using the original archive lookup, including
further native insertions and the sentinel edge described above. These results
support the guarded transformation under the tested contract.

They do not validate the full Windows adapter in a running game, establish that
every affected modlist satisfies the contract, identify the original corrupting
write, or prove save integrity. No save serialization callback or save-file write
is added by this plugin, but incorrect resource state could still affect later
game behavior. Use a separate test profile and copied saves for the outstanding
checks in the [validation record](validation.md).
