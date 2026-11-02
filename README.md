# FreezeFixF4

An experimental F4SE plugin for **Fallout 4 1.10.163** that repairs a narrowly
defined failure in the game's archive resource index. Version 2 replaces the
original watchdog-based workaround with a guarded rebuild on the engine's own
writer thread, before the affected insertion begins.

**The recovery algorithm has passed synthetic tests, including checks against the
original insertion and lookup machine code. Windows plugin execution, a live-game
reproduction, and save/reload validation are still pending. This is not a claim
that the plugin is proven safe for an existing playthrough.** See the
[validation record](docs/validation.md) for the evidence and remaining checks.

## What it fixes

The affected routine belongs to `BSResource::Archive2::Index`: it maps resource
name IDs to archive indices. A broken collision chain can make its insertion
routine loop indefinitely while the current thread holds the archive writer
lock. Other threads then wait for resources, which can present as a frozen main
menu or a stalled load. The earlier description of a movie-definition table was
incorrect; movie loading is one consumer of the archive resources.

When the original keys and every existing external index are still present and
unambiguous, FreezeFixF4 can reconstruct the collision links in a private buffer,
include the pending insertion, and commit the result under the original writer
lock. It preserves every existing key-to-index mapping and uses the existing
allocation and capacity. It also avoids selecting slot `0xFFFF` as an overflow
link, because that value encodes the end of a chain.

This is a concrete index repair, not a timing change. It does **not** establish
what originally damaged a particular player's table, fix arbitrary freezes, or
recover already-lost archive membership. It declines states for which the
required invariants cannot be established. A declined call retains the game's
original behavior, including the possibility of the original hang.

The [engine contract](docs/engine-contract.md) documents the native routines,
layout, identity checks, repair conditions, and limitations.

## Requirements

| Component | Requirement |
|---|---|
| Game | Fallout 4 **1.10.163.0**, x64; matching loaded routine hashes |
| Script extender | F4SE for 1.10.163; the vendored SDK headers are from 0.6.23 |
| Address Library | `Data\F4SE\Plugins\version-1-10-163-0.bin`, with the expected IDs and RVAs |
| Compatibility | The checked engine routines must match the documented profile when hooks are installed |

Runtime version and Address Library entries alone do not authorize a hook. The
plugin also checks complete native routine hashes after F4SE's `PostPostLoad`
message. An unsupported or already-patched routine makes the plugin stay inert;
it does not attempt to chain an unknown detour. This conservative check can
exclude otherwise legitimate mod combinations. Before any rebuild is committed,
the adapter checks the original routine bodies and its own installed hook again;
a later code change makes that recovery attempt decline.

## Build and test

On Windows, install Visual Studio C++ Build Tools with the x64 compiler and
Windows SDK. From the repository directory, run:

```bat
test.bat
build.bat
```

The scripts locate the installed C++ tools when `cl` is not already on `PATH`.
The DLL output is `build\FreezeFixF4.dll`. The required F4SE headers and MinHook
sources are vendored; the Windows plugin links against `bcrypt` for SHA-256.

The portable core tests can also run through CMake with a C++17 compiler:

```sh
cmake -S . -B build-tests -DFREEZEFIX_BUILD_PLUGIN=OFF
cmake --build build-tests --config Release
ctest --test-dir build-tests -C Release --output-on-failure
```

An optional Linux x86-64 harness executes the verified original insertion and
lookup routines against synthetic tables. Supply your own matching, legally
obtained unpacked executable:

```sh
python3 tests/run_native_validation.py --exe /path/to/Fallout4.exe.unpacked.exe
```

The script verifies the reference executable and routine hashes before execution.
It also accepts `--routines /path/to/your/extracts`. No game executable or full
routine extract is distributed in this repository. The harness does not launch the
game or read saves. These tests validate bounded index behavior; they do not
validate F4SE hook installation or actual gameplay.

## Install for controlled testing

1. Create a separate mod-manager profile with separate saves, and copy the saves
   you want to test. Keep the originals outside the test profile.
2. After building, copy `FreezeFixF4.dll` and the supplied `FreezeFixF4.ini` into
   that profile's `Data\F4SE\Plugins\` directory. Keep the matching Address
   Library installed.
3. Launch through F4SE and inspect `Data\F4SE\Plugins\FreezeFixF4.log`. Confirm
   the version and installation result before trying the affected load.
4. Follow the [validation checklist](docs/validation.md), including reloads of
   saves created in the test profile. A responsive menu alone does not establish
   a successful repair or save safety.

No released DLL is produced by the source-level test results. Keep this build in
the test profile until the outstanding Windows and in-game checks are complete.

## Configuration

The optional INI lives next to the DLL. These are the defaults:

```ini
[FreezeFixF4]
Enabled=1
Fix=1
MonitorLockWaits=0
StallMilliseconds=3000
PollMilliseconds=250
```

| Setting | Meaning |
|---|---|
| `Enabled` | `0` disables installation of all hooks. |
| `Fix` | `1` enables the constrained archive-index recovery hook. `0` disables it. |
| `MonitorLockWaits` | `1` additionally records long read-lock waits. Default `0` avoids this extra hook on a frequently called function. |
| `StallMilliseconds` | Diagnostic wait threshold, clamped to 1,000–60,000 ms; it never triggers a repair or unlock. |
| `PollMilliseconds` | Event-drain and optional monitor interval, clamped to 50–5,000 ms. |

For passive wait diagnostics, use `Fix=0` and `MonitorLockWaits=1`. With both set
to `0`, no hooks are installed. `BreakMilliseconds`, `WriterCpuPercent`, and
`SpinSamples` are obsolete, logged, and ignored. There is no forced-unlock or
watchdog-repair option in version 2.

## Reading the log

| Event | Meaning |
|---|---|
| `installed` | The verified hooks were installed; this does not mean a repair occurred. |
| `REBUILT` | The guarded repair preserved the existing membership and included the pending insertion. |
| `DECLINED` | A guard or staging check failed. The plugin did not authorize a repair of that state. |
| `INERT` | Configuration, identity, dependency, or installation checks prevented activation. |
| `LONG_WAIT` | Optional passive observation of a wait. A long wait alone is not proof of a deadlock. |

The heartbeat reports rebuilds, declines, and diagnostic overflow counts. Event
records are bounded and drained outside the engine hook; an overflow can omit an
individual event, so retain the heartbeat as well as the incident lines. A log
larger than 2 MiB is rotated to `FreezeFixF4.log.1` on the next startup.

If installation fails after a hook has already become callable, recovery remains
inactive and the DLL, trampolines, and associated resources remain resident until
process exit. Any retained hook passes through to the original function. This
avoids freeing a trampoline that an in-flight callback might still use.

## Safety boundaries

The repair requires the exact caller, matching executable profile, current writer
ownership, readable and writable bounds, coherent counts, unique keys, complete
membership, and an unchanged snapshot before commit. A healthy table proceeds
through the native insertion routine. Ambiguous data is not repaired.

The runtime watchdog only drains events and optionally observes waits. The old
thread-context sampling, remote chain edit, forced lock reset, and permanently
parked owner are removed. MinHook can still briefly suspend threads as part of
normal hook installation; that is separate from recovery during gameplay.

This plugin does not write save files or register save serialization callbacks.
That fact cannot prove that a bad in-memory resource mapping would have no later
effect on a save. The guard design and tests provide evidence for the specific
index transformation, not a guarantee against every mod interaction, unrelated
memory corruption, or future save problem.

## Third party

- `third_party/minhook`: MinHook, BSD-2-Clause, copyright 2009–2017 Tsuda Kageyu.
- `third_party/f4se`: `PluginAPI.h` and `f4se_version.h` from the
  [F4SE 0.6.23 SDK](https://f4se.silverlock.org/), included for standalone builds.

The [previous implementation plan](F4SE_FreezeFix_Plan.md) is superseded.
