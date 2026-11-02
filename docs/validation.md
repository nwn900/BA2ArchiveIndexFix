# Validation record and remaining limits

This change replaces the original watchdog mutation with a narrowly guarded
archive-index rebuild. The evidence below supports that implementation; it is
not a claim that every freeze is this bug or that all mod combinations are safe.

Version 2.0.1 recognizes bounded archive accessor detours and reports why a code
identity was accepted or rejected. The user's subsequent target run confirmed
that those identity checks passed and installation succeeded, but reported zero
rebuilds, declined pending indices between 286 and 592, and the same freeze.
**The extended-storage target remains unsupported and unresolved.**

Version 2.0.2 corrects capacity provenance and repeated-decline diagnostics. It
does not expand recovery beyond the existing fixed-key contract. The earlier
`capacity=0` on the early extended-storage decline was a literal placeholder
logged before any header capture. It was not a measurement of the native table.
The [focused investigation](extended-archive-blocker.md) records the source and
native evidence behind this boundary.

## Reported target observations

| Observation from the user's 2.0.1 run | What it establishes |
|---|---|
| Accepted detours and matching normalized SHA-256 | The four supported accessor windows and the native remainder passed the installed identity check. |
| `installed` | The verified hooks installed in that run. |
| Zero rebuilds; pending indices 286–592 declined | The reported calls were outside the supported storage range and did not exercise successful recovery. |
| The same freeze | The reported target problem was not resolved by that run. |
| Early decline printed `capacity=0` | Only the old placeholder behavior; it provides no native-capacity evidence. |

These are user-reported observations, separate from the local tests below. They
do not identify the precise stalled table contents, prove the entire installed
Daytripper helper implementation, or establish save/reload safety. The negative
result supersedes the earlier statement that installation in this target had
not yet been tried.

## Portable automated tests

`tests/core_tests.cpp` tests the production model and support code without
loading Fallout 4. The current **22-group** Linux C++17 suite passes with warnings
as errors. Its existing archive and support-code coverage includes:

- Clock samples that precede a wait start, stale tokens, recursive calls,
  registry collisions/exhaustion, repeated reporting, and concurrent snapshots.
- Address-library size/count bounds, truncated records, duplicate or unordered
  IDs, missing required IDs, wrong RVAs, and complete-file validation.
- Hook installation order and cleanup failures.
- Healthy tables left alone; cyclic, orphaned, and invalid-link topology;
  preservation of every external member index; full 12-byte key identity;
  rejection of missing/duplicate members, duplicate keys, inconsistent metadata,
  aliasing output, and insufficient space.
- The distinction between slot `0xFFFF` as a valid direct hash home and its
  invalid use as an overflow-link target.
- 600 deterministic generated repair cases with independently constructed
  fixtures and a separate lookup oracle. The tests check every existing member,
  the incoming member, absent-key behavior, and source immutability.

The 22-group portable suite also passed an AddressSanitizer/UndefinedBehaviorSanitizer
run in the audit environment. Leak detection was disabled because that sandbox
does not allow the process inspection it requires; this is not a leak-check
result. Sanitizers exercised the portable code, not the Windows adapter or game.

### Version 2.0.1 detour checks

The added portable groups cover exact native windows, allowed NOP/original tails,
signed relative targets and overflow, supported relays, cycles and hop limits,
module resolution, every fixed byte of the four supported anonymous stubs, exact
continuation addresses, and first-difference CRC32 diagnostics.

The reference windows were checked against the previously verified executable
extracts. Their lengths are **14, 17, and 8 bytes** in `archive_add`, and **8
bytes** in `archive_lookup`. Independent source-derived fixture definitions are
in [detour_fixtures.h](../tests/detour_fixtures.h). An emit-only research harness
used the Xbyak 7.28 dependency selected by
[Daytripper4's pinned vcpkg manifest](https://github.com/mith0077/Daytripper4/blob/9be6356ae34bae9094f82e3f69c87e18c9f5fb75/vcpkg.json)
to check the OG stub encodings against its
[v1.4.9 patch source](https://github.com/mith0077/Daytripper4/blob/9be6356ae34bae9094f82e3f69c87e18c9f5fb75/src/Patches/ExtendedArchiveLimit/Archive2IndexHook.cpp).
The emitter did not execute the generated machine code.

The 12-group Windows adapter suite includes cases for the production identity
validator, normalized SHA-256 checks, anonymous relay/stub resolution, retained
evidence, diagnostic formatting, and the index-255 storage boundary. The
[2.0.1 workflow](https://github.com/nwn900/FreezeFixF4/actions/runs/41532024425)
passed the x64 DLL build, 22 portable groups on Linux and Windows, and all 12
Windows adapter groups at commit
`aee081fba1844813a8b95f9b966ba66c0d0ea678`. These are synthetic cases, not
execution of the user's Daytripper DLL or a reproduction of the affected modlist.

All 1,248 diagnostic prefix CRC entries were independently checked against the
SHA-256-verified reference routines. The reproducible checker requires your own
matching reference executable:

```sh
python3 tests/generate_runtime_fingerprints.py --exe /path/to/Fallout4.exe.unpacked.exe --check
```

It also accepts `--routines /path/to/own-extracts`, containing
`archive_insert.bin`, `archive_add.bin`, `archive_lookup.bin`,
`archive_owner.bin`, and `lock_read.bin`. Each input routine's length and full
SHA-256 must match before its metadata is used. `--check` leaves the repository
unchanged. The repository contains the 47 bytes defining the allowed native
windows and diagnostic fingerprints; it contains no full native routine fixture.

### Version 2.0.2 diagnostic checks

The Windows suite now contains **14 groups**, adding coverage for raw header
observations, capacity provenance, unavailable reads, repeated-decline sampling,
and aggregate counts. The production decline still leaves extended recovery
disabled and passes the original call through. The new installation diagnostic
states the fixed-key storage contract and exclusive pending-index limit.

The [PR checks](https://github.com/nwn900/FreezeFixF4/pull/1/checks) record the
2.0.2 DLL build and execution of the 14-group Windows suite by exact revision.
The successful 2.0.1 workflow above does not establish those results. No 2.0.2
in-game or save/reload result is established here.

## Differential checks against original engine routines

An optional harness executes the verified original insertion and lookup
functions against synthetic, privately allocated objects on Linux x86-64 using
the Windows x64 calling convention. It does not launch the game or open saves.
The executable identity and layout evidence are in
[engine-contract.md](engine-contract.md).

The run completed **192 synthetic repair cases and 34,858 original-engine
lookup checks**, across capacities 2, 4, 8, 16, 64, 512, 32,768, and 65,536.
Original native insertion built the starting tables. A controlled topology
defect was introduced, the production repair built a replacement, and native
lookup verified all members and a missing key. When capacity and name limits
allowed, a further original native insertion and lookup also succeeded.

A separate boundary case reproduced this behavior in the original code:

1. Capacity is 65,536, the free-slot cursor is zero, and two different resource
   IDs have the same hash home.
2. Native overflow allocation selects physical slot `0xFFFF`.
3. Insertion returns success, but that link value means end-of-chain to native
   lookup, so the new member is reported missing.
4. The staged replacement preserves both members and makes both discoverable
   by the original native lookup.

This establishes an actual native boundary defect and validates the replacement
under that fixture. It does **not** establish why a particular modded game grew
this index to that capacity, nor prove that this defect caused a user's freeze.

### Added split-storage counterexamples

Two additional synthetic cases passed review and local native execution:

1. **Correct extended-key construction does not fix the collision reader.** A
   table is built using the actual key for member 255. Fixed slot 255 then holds
   an opaque vector-pointer stand-in, matching the reviewed split-storage
   convention. The hash home is an ordinary member below 255, so Daytripper's
   first comparison would use the same native address in this fixture. The
   unchanged native collision path reads fixed slot 255 and reports the true
   extended key missing. This isolates why a correct extended key snapshot and
   rebuild alone cannot complete the fix.
2. **The count alias can reproduce the original predecessor spin.** Native
   insertion reads index 256's apparent hash from the active-count field; the
   normal count increment changes that value. A later controlled insertion
   enters the original predecessor loop. An alarm after two seconds samples the
   instruction pointer in an expendable child process and requires it to fall
   within insertion offsets `+0x100..+0x10A` before exiting the child. An early
   return, crash, or sample outside that loop fails the case.

The first case uses native insertion and lookup; the second uses native
insertion. Neither executes Daytripper's DLL or dereferences the opaque pointer
stand-in. Both use controlled allocated storage. They are additional checks,
not additions to the historical **192 repair cases / 34,858 lookup checks**
counts, and do not prove that the user's live table contained either fixture.
The [investigation](extended-archive-blocker.md#3-native-code-that-still-uses-the-fixed-array)
connects the tested accesses to the reviewed source and verified native offsets.

### Reproduce the optional native checks

No proprietary executable or machine-code fixture is included in this repo.
On Linux x86-64, provide a legally obtained unpacked executable with the exact
documented SHA-256:

```sh
python3 tests/run_native_validation.py --exe /path/to/Fallout4.exe.unpacked.exe
```

Alternatively, provide a directory containing `hash-routine.bin` and
`archive-find.bin`, extracted at the documented RVAs. The driver verifies the
exact function lengths and SHA-256 hashes before compiling or executing the
harness:

```sh
python3 tests/run_native_validation.py --routines /path/to/own-extracts
```

The harness uses `g++` by default (`CXX` can select another compatible compiler),
keeps assertions enabled, and imposes a process timeout. The driver detects GCC
and supplies `-maccumulate-outgoing-args` for calls from Linux code into the
Windows x64 ABI routines; it does not add that GCC-specific option for Clang.
This corrects a mixed-ABI test-harness issue seen during review, rather than a
game-code change. The harness refuses mismatching native code. These checks are
optional and are not part of CI because CI has no game binary.

## Windows build and adapter tests

For the **original implementation**, the x64 MSVC DLL build, all 18 portable test
groups on Linux and Windows, and all eight Windows adapter test groups passed the
[initial implementation workflow](https://github.com/nwn900/FreezeFixF4/actions/runs/41524465613)
for commit `ef94536be466b8b7222e932691acff656e06bca1`: 26 test groups on Windows,
including the portable and adapter suites. This historical result does not cover
later changes. The separate 2.0.1 run above passed 22 portable plus 12 adapter
groups on Windows. The 2.0.2 14-group adapter suite requires its own workflow
result; the [PR checks](https://github.com/nwn900/FreezeFixF4/pull/1/checks) record
verification by revision.

The original Windows adapter tests use allocated synthetic engine objects and
the actual production adapter to exercise:

- Ownership, layout, metadata, alignment, overlap, and memory-page guards.
- Repeated capture/comparison after changes to entries, keys, and headers.
- Rejection of missing, changed, or unreadable code evidence before commit.
- Successful publication with byte-for-byte preservation of keys, count, lock,
  allocation pointer, unrelated object fields, and surrounding memory.
- Pass-through behavior for inactive or unrecognized hook call sites.
- Our installed jump/relay verification, including both displacement signs and
  tampering with the entry, relay opcode, and destination.
- Windows BCrypt SHA-256 against a standard known-answer vector.

These tests do not reproduce the real F4SE loader, the complete engine thread
schedule, other plugins' behavior, or a real game/save lifecycle.

## Compatibility scope still requiring runtime evidence

The identity check accepts native code or the four bounded accessor windows
described in the [engine contract](engine-contract.md). It verifies the supported
route to a loaded executable module and requires the full normalized routine
hash. It also retains the actual loaded routine, parsed relay/stub bytes, pointer
cells, module mapping, and sixteen-byte helper prefixes for revalidation. This
does not verify the complete semantics of arbitrary loaded helper functions.

Daytripper4's reviewed
[extended storage implementation](https://github.com/mith0077/Daytripper4/blob/9be6356ae34bae9094f82e3f69c87e18c9f5fb75/src/Patches/ExtendedArchiveLimit/ExtendedArchiveDef.cpp)
uses native slot 255 as a vector pointer. The compatibility path therefore
declines pending indices 255 and above and leaves the native call in place. The
core continues to support up to 256 keys in the stock profile; this is not an
implementation of Daytripper's extended storage. The reported target indices
286–592 are outside the repaired subset. Source/native analysis also identifies
fixed-base accesses left in insertion, later lookup comparisons, and growth;
merely raising the bound or snapshotting extended keys would not address them.

An exact installed `Daytripper4.dll` or its official distribution archive is
needed to establish the complete helper implementations, binary fingerprint, and
vector ABI before extending that contract. Module RVAs and short helper prefixes
are insufficient. A full game process dump is not required for that initial
compiled-code investigation. The
[extended-storage investigation](extended-archive-blocker.md) records the
available evidence and remaining gates.

An `accepted-detour` log confirms that the identity rejection was overcome for
that routine. An `installed` line confirms installation. A `REBUILT` event
confirms that a guarded transformation occurred. These are different claims;
none alone proves that the original freeze or a later save problem is resolved.

## Required in-game validation before calling recovery proven

The user has tested 2.0.1 installation in the affected session and reported that
the freeze remains. No successful recovery or save/reload validation has been
reported. The following checks remain for a case that actually meets the
supported recovery contract; 2.0.2 diagnostics alone do not make the reported
extended-storage target eligible:

1. Use an isolated mod-manager profile and copies of the existing saves. Keep
   an untouched baseline outside that profile. Start with the documented
   runtime and default configuration, then confirm the log says the constrained
   rebuild was installed. For the reported detour case, retain the complete
   `CODE_IDENTITY` or rejection lines, including hashes, first/remaining
   differences, and module RVAs. Retain capacity provenance, raw-header samples,
   and heartbeats for an unsupported-storage run. `INERT` or `DECLINED` is a guard
   result, not a repair.
2. Repeat the original reproduction sequence, including opening the affected
   menus and loading the resources that previously failed. Compare repeated
   runs with FreezeFixF4's `Fix=0` and `Fix=1` in the same test profile, keeping
   the rest of the modlist and its configuration unchanged. Record the log and
   whether a `REBUILT` event actually occurred. A run with no rebuild does not
   demonstrate that this fix resolved a freeze.
3. If recovery occurs, check affected resource availability and normal gameplay,
   create a new test save, exit, and reload it. Test transitions and a longer
   session before replacing a daily-use build. Preserve the baseline and logs
   if results differ.

The DLL does not register save serialization callbacks or edit save files.
Its live resource-index changes can still affect what the game does afterward,
and any resulting game state can subsequently be saved by the game. Code review
and synthetic tests cannot certify every such consequence. Unknown layouts,
ambiguous membership, lost entries, and conflicting code changes are reasons
to decline a rebuild; the native hang may remain in those cases.
