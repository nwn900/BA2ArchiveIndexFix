# FreezeFixF4

An F4SE plugin for **Fallout 4 1.10.163** that fixes a reproducible deadlock in the
main-menu / movie-loading path.

## The bug

A thread spins forever inside a hash-chain walk in `Fallout4.exe`:

    1b773f3  movzwl (%rdx,%rcx,4),%ecx     ; next = chain[i]
    1b773f7  cmp    %ebx,%ecx              ; == target bucket?
    1b773f9  jne    1b773f0                ; no -> keep walking

The loop only exits when `next` equals the target bucket. If the chain runs off into
the empty sentinel (`0xFFFFFFFF`), `next` becomes `0xFFFF`, which points at itself, and
the walk never terminates.

That thread holds a `BSReadWriteLock` for write (movie-definition table,
`_lock = 0x80000001`). Any thread that calls `lock_read` on it blocks in
`BSReadWriteLock::lock_read` -> `SleepEx` forever:

* main thread blocks -> the game freezes at the main menu, both task queues stall;
* a worker blocks -> the menu renders empty, save loads never start.

## What the plugin does

1. **Spin breaker (primary).** A watchdog samples per-thread CPU and RIP. When a thread
   burns CPU inside that loop, it repairs the chain link (points the stuck entry's `next`
   at the bucket the loop wants) so the insert completes normally and the movie registers.
2. **Lock breaker (fallback).** If a thread is still stuck in `lock_read` on a lock whose
   owner is spinning, it clears the writer bit so the reader can proceed.

Only mechanism 1 fired in the verified run; mechanism 2 is a last resort and leaves the
owner parked.

## Build

Requires Visual Studio 2022 (MSVC, x64) and the MinHook sources already vendored under
`third_party/minhook`.

    build.bat

Output: `build/FreezeFixF4.dll`.

Offline check of the address-library parser:

    test.bat
    build\addrlib_test.exe "E:\SteamLibrary\steamapps\common\Fallout 4\Data\F4SE\Plugins\version-1-10-163-0.bin"

## Install

Copy to `Data\F4SE\Plugins\`:

* `FreezeFixF4.dll`
* `FreezeFixF4.ini` (optional)

```ini
[FreezeFixF4]
Fix=1
BreakMilliseconds=3000
PollMilliseconds=250
WriterCpuPercent=40
SpinSamples=4
```

The plugin refuses to load on any runtime other than 1.10.163, and stays inert if the
Address Library (`version-1-10-163-0.bin`) or a needed ID is missing.

## Log

`Data\F4SE\Plugins\FreezeFixF4.log`, appended and shareable while the game runs.

    [20:56:26.604] SPIN tid=18468 rip=+0x107 rcx=0xFFFF rbx=0x2
    [20:57:10.888] heartbeat calls=32934830 incidents=0 breaks=0 defers=0 spins=1

## Status

Verified on the reference modlist (~190 F4SE plugins, 257 modules): the menu renders, the
missing-content dialog appears, and the last quicksave (level 159) loads to a playable
game. `breaks=0` in that run — the spin breaker alone was sufficient.

Known limits:

* Only 1.10.163. Addresses come from the Address Library, so a game patch disables it.
* The chain repair fixes the symptom at the stuck point; it does not explain what
  corrupts the chain. That is the upstream bug, and it belongs to the engine or F4SE.
* The lock-breaker fallback parks the owning thread, which can leave a movie unregistered.

## Third party

* `third_party/minhook` - MinHook, BSD-2-Clause, (c) 2009-2017 Tsuda Kageyu.
* `third_party/f4se` - `PluginAPI.h` and `f4se_version.h` from the F4SE 0.6.23 SDK
  (<https://f4se.silverlock.org/>), included so the project builds standalone.

See `F4SE_FreezeFix_Plan.md` for the full analysis, hook strategy and validation plan.
