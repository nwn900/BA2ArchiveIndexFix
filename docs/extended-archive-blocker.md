# Extended archive storage: unresolved target and evidence

**FreezeFixF4 2.0.2 does not repair the reported Daytripper extended-storage
case.** It corrects the diagnostics from 2.0.1 and retains the guard against
rebuilding pending indices 255 and above when archive detour compatibility is
active. The native call still runs after a decline and can still hang.

This document separates three sources of evidence: the user's reported target
run, the reviewed public Daytripper source and verified native routines, and
synthetic local tests. It does not present a source-level defect candidate as a
captured root cause of the user's freeze.

## 1. What the target run established

The user reported a 2.0.1 run in which:

- The archive accessor detours were accepted and the normalized routine hashes
  matched the reference.
- The hooks installed.
- Rebuilds remained zero; pending indices between 286 and 592 were declined with
  `extended-archive-storage-unsupported-at-index-255-or-above`.
- The same freeze occurred.

This establishes that the earlier identity rejection was overcome in that run.
It also establishes that the reported run did not exercise a successful repair.
It does not establish the table's capacity, which index caused the eventual
freeze, whether another object was also involved, or the complete semantics of
the installed external helper functions.

### Why `capacity=0` was misleading

In 2.0.1, `TryRebuild` tested the extended-storage boundary before calling
`CaptureIndex`, then passed a literal zero to the event logger. The field did not
come from native memory. It cannot support a diagnosis of a zero-capacity table,
a wrong table offset, or a damaged header.

Version 2.0.2 labels capacity provenance explicitly. On sampled extended-storage
declines it attempts one complete 32-byte read at the table address, prints the
eight raw 32-bit words, and labels the word at `+0x10` as
`raw-header+0x10-unvalidated`. A failed read is `unavailable`. No pointer field is
followed and no repair is authorized by this diagnostic. Readability alone does
not validate the layout or its contents.

Samples occur at cumulative reason counts 1, 2, 4, 8, and so on across all table
objects. Every decline updates `extended_declines` and the maximum
`highest_extended_incoming`; intentional suppression is counted separately from
event-queue overflow. These fields explain why a later heartbeat may report a
higher incoming index than the last sampled event. See the
[log guide](../README.md#reading-the-log) for field meanings.

## 2. The reviewed storage contract

The public source is Daytripper4 1.4.9, pinned to commit
[`9be6356ae34bae9094f82e3f69c87e18c9f5fb75`](https://github.com/mith0077/Daytripper4/tree/9be6356ae34bae9094f82e3f69c87e18c9f5fb75).
Its [root build file](https://github.com/mith0077/Daytripper4/blob/9be6356ae34bae9094f82e3f69c87e18c9f5fb75/CMakeLists.txt)
sets version 1.4.9. This source pin identifies what was reviewed; it is not a hash
of the user's installed DLL.

In
[ExtendedArchiveDef.cpp](https://github.com/mith0077/Daytripper4/blob/9be6356ae34bae9094f82e3f69c87e18c9f5fb75/src/Patches/ExtendedArchiveLimit/ExtendedArchiveDef.cpp#L18-L34),
the last fixed-array element, index 255, is repurposed to store a pointer to a
new `std::vector<ResourceID>`. The
[name-ID accessor](https://github.com/mith0077/Daytripper4/blob/9be6356ae34bae9094f82e3f69c87e18c9f5fb75/src/Patches/ExtendedArchiveLimit/ExtendedArchiveDef.cpp#L101-L122)
returns the fixed element below 255 and vector element `index - 255` otherwise.
It grows the vector in blocks of 256 under a helper-local mutex and returns a
reference. The vector's size therefore need not equal the active archive count.
The header's older `BSTArray` comment does not describe this implementation.

Using the verified native parent-object layout:

| Location | Parent-relative offset | Meaning |
|---|---|---|
| Fixed name-ID array | `+0x1030` | Twelve bytes per original key |
| Fixed slot 255 | `+0x1C24` | Holds the vector pointer under the reviewed extension |
| Active count | `+0x1C30` | Number of active archive IDs |
| Writer lock | `+0x1C58` | Original owner/state fields |
| End of reviewed parent object | `+0x1C60` | Fixed-array index 260 starts here |

The table pointer passed to BaseInsert is parent `+0x10`. These offsets are from
the parent; the [engine contract](engine-contract.md#3-object-and-entry-layout)
also lists the table-relative layout.

## 3. Native code that still uses the fixed array

Daytripper redirects the incoming key's write destination in
[AddDataFile_2](https://github.com/mith0077/Daytripper4/blob/9be6356ae34bae9094f82e3f69c87e18c9f5fb75/src/Patches/ExtendedArchiveLimit/Archive2IndexHook.cpp#L283-L310)
and the first lookup address calculation in
[GetDataFileIndex](https://github.com/mith0077/Daytripper4/blob/9be6356ae34bae9094f82e3f69c87e18c9f5fb75/src/Patches/ExtendedArchiveLimit/Archive2IndexHook.cpp#L372-L414).
The following remaining accesses were recovered from the verified 1.10.163
native routines:

| Operation | Native RVA / routine offset | Access |
|---|---|---|
| Prepare insertion key base | `0x1B7685C`, `archive_add +0x6C` | Computes parent `+0x1030`; the pointer is stored at `0x1B7686D` for the insertion argument |
| Hash incoming member | `0x1B77315`, `archive_insert +0x25` | Reads word zero through the supplied fixed key base |
| Hash displaced member | `0x1B77392`, `archive_insert +0xA2` | Reads the occupant's word zero through that same base |
| Compare a later chain member | `0x1B78BAB`, `archive_lookup +0xBB` | Computes parent `+0x1030 + 12*index`; reads the key at `0x1B78BB3`, `0x1B78BBA`, and `0x1B78BCE` |
| Rehash a member during growth | `0x1B7B7C1` | Reads through the key-array reference passed to grow at `0x1B7B740` |
| Hash a displaced member during growth | `0x1B7B823` | Uses that same key-array reference |

The runtime identity checks cover the complete insertion, AddDataFile, and lookup
ranges. Normalization restores only the four accepted accessor windows in a
private validation copy. A successful normalized hash therefore covers the
native remainder containing the insertion and collision-loop accesses above.
The growth routine was inspected separately and is **not** among the current
runtime fingerprint ranges. Neither kind of evidence proves an external
helper's complete behavior.

This mismatch has concrete consequences. At fixed index 255, the native code
reads pointer bytes as an ID. At fixed index 256, its apparent key starts at
parent `+0x1C30`, so its hash word aliases the mutable count. Incrementing the
count can change the apparent hash of an already inserted member. At index 260,
fixed-array addressing begins beyond the reviewed object extent.

Growth is not a generic escape from this state. It doubles capacity, publishes
new live header fields at `0x1B7B76D..0x1B7B77D`, rehashes through the supplied
key base, and releases the old slot array at `0x1B7B8C7`. Its predecessor walk
also assumes a reachable member. Returning false to force that path would not
establish correct extended-key access or a safe retry.

## 4. Local native counterexamples and their limits

The optional [native harness](../tests/native_engine_check.cpp) passed two
additional split-storage fixtures in a local run of the production driver,
alongside the existing 192 repair cases and 34,858 native lookup checks:

1. Build a correct table using the true extended key for index 255, then retain
   an opaque pointer stand-in in fixed slot 255. Its hash home contains an ordinary
   member below 255, and index 255 is a later chain member. The reviewed
   extension's first comparison is equivalent to the native comparison for that
   ordinary member. The unchanged collision loop then reads the wrong key from
   fixed slot 255 and reports the true extended key missing. This demonstrates
   why rebuilding with true keys alone is insufficient for this fixture.
2. Construct the pointer/count-alias state and let the count increment change
   index 256's apparent hash. A subsequent native insertion entered
   the predecessor spin at insertion offsets `+0x100..+0x10A`. The harness runs
   this expected hang in a child process and checks the sampled instruction
   pointer before terminating the child; an ordinary early return, crash, or
   timeout elsewhere fails the check.

The [validation record](validation.md) records these results and the compiler ABI
option required by the Linux-to-Windows native-call harness. The fixtures use
the verified native instructions and controlled
synthetic memory. They do not execute the installed Daytripper DLL, assume its
vector ABI, read a save, reproduce the complete modlist, or establish that either
fixture matches the exact contents of the user's stalled table.

## 5. Evidence needed before implementing extended recovery

The useful next compiled artifact is the **exact installed `Daytripper4.dll`, or
the official archive from which it was installed**. A full game process dump is
not required for this first step. The DLL would permit a module fingerprint,
complete helper disassembly at the observed module RVAs, and a concrete storage
ABI profile. The observed helper RVAs (`0x1550`, `0x35D5`, and `0x28FB`), module
name, and retained sixteen-byte prefixes do not supply those proofs by
themselves.

No binary or release asset was available from the reviewed public GitHub
repository. The official
[Nexus listing](https://www.nexusmods.com/fallout4/mods/91141) identifies the
1.4.9 archive, but no copy or hash of that DLL was obtained in this investigation.
An independently rebuilt source DLL would not automatically identify the user's
installed binary.

The source uses `std::vector`, whose in-memory representation is a compiler and
standard-library ABI detail. The
[build presets](https://github.com/mith0077/Daytripper4/blob/9be6356ae34bae9094f82e3f69c87e18c9f5fb75/CMakePresets.json)
permit different toolchains. Microsoft's
[vector implementation](https://github.com/microsoft/STL/blob/e1ed302683e5e822f663fbb0f44cee7e9ddc6af0/stl/inc/vector)
uses a container base whose representation depends on iterator-debug settings in
[xmemory](https://github.com/microsoft/STL/blob/e1ed302683e5e822f663fbb0f44cee7e9ddc6af0/stl/inc/xmemory).
Assuming a three-pointer header from a nominal Release build is not sufficient
to authorize writes into this target's index.

A supported fix needs one coherent contract for actual keys during insertion,
every lookup comparison, and growth or its safe exclusion. It also needs proved
storage lifetime and synchronization, bounded extended membership validation,
and the existing revalidation/publication guarantees. Raising the count bound
or adding only a vector snapshot would leave known incompatible accesses in
place. Version 2.0.2 intentionally adds no such speculative recovery.
