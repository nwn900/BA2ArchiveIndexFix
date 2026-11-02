# Validation record and remaining limits

This change replaces the original watchdog mutation with a narrowly guarded
archive-index rebuild. The evidence below supports that implementation; it is
not a claim that every freeze is this bug or that all mod combinations are safe.

## Portable automated tests

`tests/core_tests.cpp` tests the production model and support code without
loading Fallout 4. The Linux C++17 build uses warnings as errors. Coverage
includes:

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

The portable suite also passed an AddressSanitizer/UndefinedBehaviorSanitizer
run in the audit environment. Leak detection was disabled because that sandbox
does not allow the process inspection it requires; this is not a leak-check
result. Sanitizers exercised the portable code, not the Windows adapter or game.

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
keeps assertions enabled, and imposes a process timeout. It refuses mismatching
code. These checks are optional and are not part of CI because CI has no game
binary.

## Windows build and adapter tests

The x64 MSVC DLL build, all 18 portable test groups on Linux and Windows, and
all eight Windows adapter test groups passed the
[initial implementation workflow](https://github.com/nwn900/FreezeFixF4/actions/runs/41524465613)
for commit `ef94536be466b8b7222e932691acff656e06bca1`. The workflow result attached
to the PR records verification of each subsequent revision.

The Windows adapter tests use allocated synthetic engine objects and the actual
production adapter to exercise:

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

## Required in-game validation before calling this release proven

The implementation has not been tested in a running Fallout 4 session during
this work. The following remains a manual validation task:

1. Use an isolated mod-manager profile and copies of the existing saves. Keep
   an untouched baseline outside that profile. Start with the documented
   runtime and default configuration, then confirm the log says the constrained
   rebuild was installed. `INERT` or `DECLINED` is a guard result, not a repair.
2. Repeat the original reproduction sequence, including opening the affected
   menus and loading the resources that previously failed. Compare repeated
   runs with `Fix=0` and `Fix=1` in the same test profile. Record the log and
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
