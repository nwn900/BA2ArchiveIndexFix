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
