# Extended archive validation (2.0.3)

Scope: does FreezeFixF4 2.0.3 repair a Daytripper4 archive index holding 500-600+
keys without broken lookups, lost resources, or memory corruption?

**Verdict: no. The rebuild is structurally correct, but the native collision loop
cannot retrieve extended keys that sit in a collision chain.** The freeze is
fixed; lookups are not fully fixed. Details and evidence below.

## Environment

| Item | Value |
|---|---|
| Runtime | Fallout 4 1.10.163 (packed 17435184) |
| F4SE | 0.6.23 |
| Daytripper4 | 1.4.9, source pin `9be6356` |
| Compiler | MSVC 19.x, x64 Release, `/W4` |
| CMake | 3.20+ |
| Host | Windows 11 x64 |

## Commands

```
cmake -S . -B build -A x64 -DFREEZEFIX_BUILD_PLUGIN=ON \
      -DFREEZEFIX_NATIVE_LOOKUP_ROUTINE=<path>/archive_lookup_native.bin
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

The native routine extract is not committed. It is produced from a decrypted
`.text` of the matching build by restoring the four accepted Daytripper windows;
the normalized bytes must hash to
`f4172a68a14be8e48a1117fc70c1200f78623827f0ae64826742d890a6409895`, which the
harness verifies before executing anything.

## Gate results

### Extended keys - PASS

`extended_archive_rebuild_supports_601_keys` builds 601 existing members
(indices 0..600) plus one incoming, over four homes so every chain is ~150 long
and crosses index 255 in both directions. Boundaries 0, 1, 254, 255, 256, 286,
511, 512, 592, 599, 600 are each asserted present exactly once before and after
the rebuild.

`extended_archive_generated_cases_hold_above_500_keys` runs 1000 deterministic
cases (seed `0x9E3779B9`, xorshift32) with 500..601 existing members, 1..8 homes,
and one deliberately broken chain each. Every case asserts: complete membership,
the incoming member inserted once, reachability from the correct bucket, no
cycles or invalid slots, consistent metadata, and unmodified source arrays.

### Native lookup - FAIL (the decisive result)

`freezefix_native_lookup` executes the real `archive_lookup` machine code
(identity-verified) against a table produced by the production `BuildRepair`:

```
PASS identity: native archive_lookup sha256 verified (254 bytes)
uniform: members=602
  inline   found=255 missing=0
  extended found=0 missing=347 (at-home=347 in-chain=0 chain-found=0)
uniform (daytripper stub emulated): members=602
  inline   found=255 missing=0
  extended found=347 missing=0 (at-home=347 in-chain=0 chain-found=0)
adversarial (daytripper stub emulated): members=602
  inline   found=255 missing=0
  extended found=0 missing=347 (at-home=0 in-chain=347 chain-found=0)
KNOWN LIMITATION: 347 extended keys sit in collision chains; the native
collision loop reads the fixed array and cannot retrieve them.
```

Reading:

- Inline members (0..254) are always retrievable. No regression.
- With Daytripper's `archive_lookup+0x53` detour, the **first** comparison is
  redirected to `GetDataFileNameIdEx`, so an extended key that occupies its own
  home slot is found. The uniform run shows 347/347.
- The **collision loop** at `0x1B78BAB..0x1B78BCE` computes
  `parent + 0x1030 + index*12` and reads the fixed array directly. For an
  extended member it reads the vector pointer, the count field, or memory past
  the object. The adversarial run shows 0/347.

So the rebuild produces a table the engine can only partially read. The defect
is in the native loop, not in the rebuild.

### Collisions - FAIL

Same evidence. Mixed original/extended chains lose their extended members.

### Growth - unreachable in this configuration

`0x1B7B740` reads capacity at `+0x10`, computes `max(2, capacity*2)`, allocates,
publishes the new capacity/mask, and rehashes through the supplied key base.
It runs only when the table is full. Daytripper's constructor patch sets the
capacity to 65,536 and the observed table reports `capacity=65536`; the target
modlist holds ~600 archives. Growth therefore cannot occur, and its fixed-array
rehash is not exercised. This is a reachability argument, not a test.

### Native regression - PASS

`ReadKeys` now takes an `extended` flag. Without the archive detours, slot 255 is
an ordinary key and the fixed array is contiguous, so a native table with 255
members is read as 256 keys instead of being mistaken for a vector pointer.
The adapter suite covers both paths.

### Memory safety - PASS (adapter level)

`ReadKeys` validates the vector object, its `first`/`last` fields, whole-key
alignment, and that the vector holds at least `count + 1 - 255` elements before
reading. Unreadable or inconsistent extended captures are declined and counted,
not dereferenced. The adapter suite covers unreadable headers, unreadable
vectors, and changing snapshots.

### Existing tests - PASS

`ctest`: `freezefix_core`, `freezefix_windows_adapter`,
`freezefix_native_lookup` - 3/3.

## Outstanding risks

1. **Extended keys in collision chains are unreachable.** With ~600 archives over
   65,536 buckets the expected number of collisions is ~2.7, so a handful of
   entries can be lost per session. This is a correctness defect, not a crash.
2. The rebuild runs repeatedly (172 rebuilds in one session) because the native
   insert keeps re-breaking the chain. That is a symptom of the same mismatch.
3. Growth is argued unreachable, not tested.
4. Real-game resource-level verification was not performed; only menu, save load,
   and a 1.5-hour session were observed.

## Release readiness

Not ready for public release with extended storage enabled. The freeze fix is
sound and the rebuild is structurally correct, but the native lookup criterion
fails. The fix belongs in Daytripper4 (redirect the collision loop's key read) or
in a plugin-side lookup fallback; both are outside the current contract.

## Native key-access corrections (branch `fix/extended-archive-native`)

Two mid-function corrections were implemented as call stubs that preserve the
volatile registers, ask the plugin for the real key address, and reproduce the
instruction they displaced.

### Collision-loop lookup - shipped

`archive_lookup+0xBB` now reads every chain member through the extended
accessor. Executed against the identity-verified native routine:

```
adversarial (stub):            extended found=0   missing=347 (in-chain=347)
adversarial (stub) corrected:  extended found=347 missing=0   (chain-found=347)
```

Inline members stay 255/255 in every scenario. This correction is installed when
the Daytripper detours are detected and the code identity matches.

### Native insertion - shipped

`archive_insert+0x25` and `+0xA2` are corrected the same way. Both the
adversarial (4-home) and the uniform distribution pass 601/601 insertions with
complete membership; the unpatched control corrupts the table at index 255.

The correction was briefly disabled because a uniform distribution faulted at
`archive_insert+0xED` with `r9` holding a raw key word instead of a masked home.
The cause was a one-byte encoding error in the displaced stub: it emitted
`41 23 CF` for `and r9d, edi`, but `0x41` is REX.B, which extends the *source*
operand, so the CPU decoded `and ecx, r15d` and `r9d` reached the walk unmasked.
The adversarial distribution survived because its key words are small; uniform
keys are 32-bit and ran off the array. The correct prefix is `0x44` (REX.R).

`tests/native_insert_windows.cpp` asserts both halves: the unpatched routine
corrupts the table at the first extended index, and the corrected routine inserts
all 601 keys on both distributions.

## 2.1.0 results

Both corrections are installed and verified.

| Check | Result |
|---|---|
| Native insert, adversarial (4 homes) | 601/601, 0 failures |
| Native insert, uniform hashes | 601/601, 0 failures |
| Native insert, unpatched control | corrupts at index 255 |
| Native lookup, extended in-chain | 347/347 |
| Native lookup, inline | 255/255 |
| Integration, 1000 scenarios | 0 failures |
| Real game, main menu | loads, no freeze |
| Real game, rebuilds | **0** (was 172 per session) |
| Real game, save load | level-150 save loads and is playable |

The rebuild count is the clearest signal: with the insertion corrected the engine
no longer re-breaks the chain, so the emergency rebuild never runs.

### The defect that took three rounds

The displaced-key stub emitted `41 23 CF` for `and r9d, edi`. `0x41` is REX.B,
which extends the *source* operand, so the CPU decoded `and ecx, r15d` and `r9d`
reached the predecessor walk unmasked. The adversarial distribution survived
because its key words are small; uniform keys are 32-bit and ran off the array.
The correct prefix is `0x44` (REX.R).

### Release artifacts

- `dist/FreezeFixF4-2.1.0.zip` — SHA-256 `F0529EC78AA985A4A888D0288D87CFF75FFD00949C6B470C19D3E83BEAAE4427`
- `FreezeFixF4.dll` — SHA-256 `ADA7D92B019A7C7E8195377CE5BB0D349F384BEC2516316A9952AB89B32AD660`, 349,184 bytes

### Remaining risks

- The corrections are validated against synthetic parent objects and one real
  modlist. Other archive layouts are not covered.
- Table growth remains unreachable at 65,536 slots with ~600 archives; its
  fixed-array reads are not corrected.
- The real-game pass verified menu, save load and a playable session, not
  per-resource archive lookups.

### Rollback safety (2.1.1)

A failed restore used to clear the patch's committed flag anyway, so the caller
could free a stub the still-patched engine code calls. `RollbackNativePatch` now
returns success and clears the flag only when the original bytes are back in
place; `ReleaseUnreferencedStubs` frees only stubs whose window is no longer
patched, and a stub whose window could not be restored is retained for the
process lifetime with a log line. `tests/windows_adapter_tests.cpp` injects a
forced restore failure and asserts the stub survives, then restores normally and
asserts it is freed.

The installation line now reports `all_or_nothing=1` rather than `atomic=1`: it
states that the three windows were installed as a set, not that the writes are
atomic for other threads.

`.github/workflows/release.yml` is a manual release workflow that **requires** the
native routine extracts and fails without them, so a candidate cannot be produced
from a run where the native gate was skipped.

### Installation order and the unresolved-key fallback (2.1.2)

`Install()` now pins the module and installs the hooks **before** committing the
native corrections, so a failure in either leaves the engine unmodified and an
`INERT` line is always accurate. The corrections are the last step of the
transaction.

`FreezeFixKeyAddress` no longer returns the key-array base when the extended
vector cannot be validated. It returns a static zero key.

**This is a documented degradation, not safe recovery, and it is not a fail-safe
insertion strategy.** Three things are true and none of them is a guarantee:

- A zero key is unlikely to equal a real `ResourceID`, but that is an argument
  from the tests, not a proof about every archive ID the engine can hold.
- An insertion hashes the zero key into bucket 0 even though the real key belongs
  elsewhere, so the table is left with a member in the wrong bucket.
- The rebuild cannot be relied on to repair that. The rebuild hook runs *before*
  the native insertion, and if the extended vector is unreadable the rebuild's own
  snapshot validation fails too, so it declines and the native insertion proceeds.

There is no safe way to abort the insertion from inside the patched routine. The
hook's two outcomes are both worse: returning false sends the caller down the
engine's table-growth path, which rehashes through the same fixed array, and
returning true without inserting increments the active count while leaving the
member out of the table, which makes every later rebuild decline on a count
mismatch. The zero key at least keeps membership intact, so a later rebuild can
repair the bucket once the vector is readable again.

Rejections are counted in `key_failures` and reported in the heartbeat. In the
tested configuration the vector is grown by Daytripper's own accessor before the
insertion runs, so this path has not been observed; it exists for the case where
the storage contract is not what was validated.

### Release workflow status

`.github/workflows/release.yml` requires the native extracts and fails without
them. Its steps were exercised locally with `FREEZEFIX_REQUIRE_NATIVE_TESTS=ON`:
five tests registered, five passed. The workflow itself has **not** been
dispatched on GitHub, because manual dispatch requires the workflow to exist on
the default branch and this branch is not merged.

### Partial installation blocks startup (2.1.4)

A partial installation leaves the engine with an incomplete correction set, and
because the code contract is only updated after all three windows commit, the
emergency rebuild is then rejected by code validation too. The claim that the
rebuild remains available as recovery is therefore false in that state.

`ShouldBlockStartup` treats an unrecoverable partial installation as a
startup-blocking failure: the plugin logs `startup blocked: partial installation
residual=N`, shows a message box naming the log path, and terminates the process
before gameplay. A clean decline (nothing installed, engine unmodified) still
continues normally.

`tests/windows_adapter_tests.cpp` asserts the decision for all three states:
complete, cleanly declined, and partial.
