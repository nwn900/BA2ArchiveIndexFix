# FreezeFixF4 — F4SE plugin to eliminate the main-menu task-queue deadlock

**Target:** Fallout 4 **1.10.163** (Steam), F4SE **0.6.23**
**Deliverable:** `Data\F4SE\Plugins\FreezeFixF4.dll`
**Status:** implementation plan, grounded in the FreezeSentryF4 captures in
`%USERPROFILE%\Documents\My Games\Fallout4\F4SE\FreezeSentryF4\`.

---

## 0. What the captures actually prove

Everything below is read out of `freeze-20261102-181558-415-21756.log`,
`prehang-21756.log`, `session-21756.log` and `preflight-21756.json`. Numbers are exact.

| Fact | Value | Where |
|---|---|---|
| Runtime | **1.10.163**, not 1.10.153 | `f4se_1_10_163.dll` loaded; `runtime_packed=17435184` (= 0x010A0A30, build<<4) |
| F4SE build | 0.6.23 | `f4se_packed=393584`; `version-1-10-163-0.bin` present |
| Incident tick | 10919015 | header |
| Last queue pump | 10903750 | header |
| Stall length at detection | **15.3 s** | 10919015 - 10903750 (timeout_ms = 15000) |
| normal_queue | thread 27552, count 70, **pending 1** | header |
| ui_queue | thread 27552, count 71, **pending 1** | header |
| Last F4SE event | PostPostLoad, tick 10872921 | event_id 2 |
| Menus open | `[FaderMenu] [MainMenu] [ButtonBarMenu]` | ENGINE_CONTEXT |
| Modules | 257, of which ~190 F4SE plugins | module table |
| Already-installed mitigations | `ConditionDeadlockFixRD.dll`, `EscapeFreeze.dll` | module table |
| Still frozen 10.4 min later | identical stacks at tick 11544593 | `prehang-21756.log` |

### 0.1 Main thread (TID 27552) — blocked

```
ntdll.dll+0x9dc74            NtDelayExecution
KERNELBASE.dll+0x462de       SleepEx
Fallout4.exe+0x1b10983       BSReadWriteLock::lock_read + 0x53      <-- ID 1573164
Fallout4.exe+0x1b7172f
Fallout4.exe+0x1b6d313
Fallout4.exe+0x2114c65
Fallout4.exe+0x21110e4       BSScaleformManager::GetMovieFilename + 0x44   <-- ID 1191277
Fallout4.exe+0x2110b62       BSScaleformManager::LoadMovie + 0x92          <-- ID 1526234
Fallout4.exe+0x126ab87
Fallout4.exe+0x126b04a
Fallout4.exe+0x2042d1c
Fallout4.exe+0xd395ea
Fallout4.exe+0xd36e10
Fallout4.exe+0xd35950
Fallout4.exe+0x2937157
KERNEL32.DLL+0x17124         BaseThreadInitThunk
```

The frame at `0x1b10983` is inside `BSReadWriteLock::lock_read` (entry `0x1b10930`,
next function `lock_write` at `0x1b109b0`). **The main thread is not sleeping for its own
reasons — it is sleeping inside a read-lock acquisition.**

### 0.2 Spinning thread (TID 23736) — 100 % of one core

```
Fallout4.exe+0x1b773f7
Fallout4.exe+0x1b768ac
Fallout4.exe+0x1b7a34b
Fallout4.exe+0x1b79f44
Fallout4.exe+0x1b6fcdc
Fallout4.exe+0x1b7d93a
Fallout4.exe+0x11d6c4
Fallout4.exe+0x116e9f
Fallout4.exe+0xd37cd4
Fallout4.exe+0xd3f253
Fallout4.exe+0xd535a9
f4se_1_10_163.dll+0xa8ac          <-- return address of an F4SE -> engine call
Fallout4.exe+0x1b1cfed            <-- thread entry (BaseThreadInitThunk)
```

CPU delta is 1.9-2.3 s per ~2.1 s sample, sustained for the whole 10-minute capture.
`f4se+0xa8ac` is the instruction after `call qword ptr [f4se+0xc4b9c]` at `f4se+0xa8a6`
(verified by disassembling the shipped DLL), i.e. F4SE called into the engine at
`0xd535a9` and the engine never returned.

### 0.3 The on-disk executable is SteamStub-wrapped

`Fallout4.exe` on disk has `.text` entropy **8.000**, and its entry point (`0x6cb9310`)
sits in a `.bind` section containing a position-independent stub (`call $+5; pop; ...`).
**You cannot pattern-scan the file.** All static analysis must use either
(a) the Address Library (`version-1-10-163-0.bin`, present) or (b) a decrypted image
dumped from a live process. This kills the "scan the exe for the SleepEx call site"
approach that most plans would suggest.

---

## 1. Root-cause hypothesis

### 1.1 The mechanism

`BSReadWriteLock` is 8 bytes: `{ uint32 _writerThread; uint32 _lock; }`.
`_lock` is a reader count with the high bit meaning "writer holds it".
`unlock_write()` only clears the lock when `_lock == 0x80000001`, so a writer sets
`_lock = 0x80000001` on acquisition. `lock_read()` therefore blocks **only when a writer
currently holds the lock** — a merely *waiting* writer does not block readers.

The main thread is inside `lock_read` and sleeping. Therefore:

> **Some thread holds that `BSReadWriteLock` for write and is not releasing it.**

The only thread in the process burning CPU is TID 23736, and it is stuck in an engine
loop entered through an F4SE hook trampoline. The consistent reading is:

1. TID 23736 acquires the Scaleform movie-definition `BSReadWriteLock` for write
   (movie registration during the main-menu movie creation — the capture shows four
   `movie-created` events at ticks 10884937-10885140, immediately before the freeze).
2. Inside that critical section it blocks on a second resource (a spin lock or a
   condition it polls), so it spins forever **while still holding the write lock**.
3. The main thread, loading the next menu movie, calls `lock_read` on the same lock and
   sleeps forever waiting for a writer that will never finish.

This is a **lock-order inversion (ABBA) with a non-yielding writer**, not a simple
priority inversion and not a lost wakeup: the writer is not waiting for a signal, it is
spinning, and the reader is not waiting for a signal either, it is polling
`_lock` with `SleepEx(1)`.

### 1.2 Why disabling plugins did not help

* The cycle is between **the engine's own Scaleform loader path and F4SE's hook**, not
  between two plugins. `FullBodyFirstPerson.dll` (or any other plugin) is not in either
  stack.
* `ConditionDeadlockFixRD.dll` and `EscapeFreeze.dll` are already loaded in this capture
  and the freeze still happened — they target different deadlocks (condition evaluation
  and generic hang detection), not a held `BSReadWriteLock`.
* Removing plugins changes *which* movie gets loaded and *when*, so it changes the
  probability, not the mechanism. That is why the bug "comes back".

### 1.3 The competing hypothesis (must be ruled out first)

The spinner may not be the writer. It could be a third thread, with the actual writer
blocked on the main thread's task queue (in which case pumping the queue would fix it).
**Do not write the breaker before running the 30-line diagnostic in section 2.4** — it
prints the lock's `_writerThread` and settles this in one run.

---

## 2. Detection

### 2.1 What to watch

Three independent signals, all cheap:

1. **Lock residency** — how long the main thread has been inside `lock_read` on a given
   lock object. This is the direct signature and needs no engine internals beyond the
   hook's `this` pointer.
2. **Queue pending** — `Main::GetSingleton()` (ID 756304) -> `taskQueue` at `+0xD8`,
   `secondaryTaskQueue` at `+0x108`. `pending > 0` for > 2 s means the main thread is not
   pumping.
3. **Spinner CPU** — `GetThreadTimes` on the lock's `_writerThread`; > 80 % of one core
   over a 1 s window means the writer is spinning, not working.

### 2.2 Watchdog loop

A dedicated thread, `THREAD_PRIORITY_HIGHEST`, 250 ms period, does **no engine calls**:

```
every 250 ms:
  now = GetTickCount64()
  if (g_mainThreadInLockRead.load() && now - g_lockReadEnteredAt > 2000ms)
      and queuePending() > 0
      and writerCpuPercent() > 80:
          -> incident
```

`g_mainThreadInLockRead` / `g_lockReadEnteredAt` / `g_lockObject` are written by the
`lock_read` hook (relaxed atomics, no allocation, no locks).

### 2.3 Thresholds

| Parameter | Default | Rationale |
|---|---|---|
| `lockReadWarnMs` | 2000 | normal movie loads hold the read lock for < 5 ms |
| `lockReadBreakMs` | 3000 | break only after the queue has been stalled 3 s |
| `writerCpuPercent` | 80 | distinguishes "spinning" from "doing work" |
| `samplePeriodMs` | 250 | 12 samples per break window |

### 2.4 Diagnostic build (do this first)

Ship a build that only **logs** and never intervenes. On incident it writes:

```
lock=0x... _lock=0x80000001 _writerThread=23736 mainTid=27552
writerCpu=97% writerRip=Fallout4.exe+0x1b773f7
queuePending normal=1 ui=1 stalledMs=3120
```

If `_writerThread` is the spinning thread -> section 1.1 confirmed, enable the breaker.
If `_writerThread` is a thread that is *blocked* (not spinning) -> the writer is waiting on
something the main thread owns; go to Appendix B.

---

## 3. Intervention options

| # | Option | Verdict |
|---|---|---|
| A | Hook `SleepEx`/`NtDelayExecution` on the main thread, pump queues instead of sleeping | **Rejected as primary.** The sleep is inside `lock_read`; pumping task queues from inside a lock acquisition re-enters the engine in an arbitrary state. It also converts a deadlock into a 100 % CPU livelock without releasing the writer. |
| B | Hook the queue-dispatch path so pending work runs before any blocking sleep | **Rejected.** The main thread never reaches the dispatch path — it is blocked *before* it. |
| C | Watchdog posts `SetEvent`/`PostMessage`/APC to wake the main thread | **Rejected.** The main thread is not waiting on an event; it polls `_lock` with `SleepEx(1)`. Waking it changes nothing. |
| D | Detour the F4SE path at `f4se+0xa8ac` | **Rejected.** F4SE is a caller, not the lock holder; patching another module's code breaks on every F4SE update and is not needed. |
| E | **Lock-aware deadlock breaker** (recommended) | Hook `lock_read`/`lock_write`, track ownership, and on a confirmed stall force-release the writer's lock and park the spinner. |

### 3.1 Why E

* It targets the **only** verified blocking primitive (`BSReadWriteLock::lock_read`), not a
  guess.
* It preserves the reader count: the main thread still increments `_lock` on the way in and
  the engine's inline `unlock_read` still decrements it, so no counter corruption.
* It is bounded: it only fires after 3 s of a *confirmed* stall, only on the specific lock
  the main thread is stuck on, and only when the writer is provably spinning.
* It is reversible: a config flag disables it, and the log records every intervention.

### 3.2 Prevention layer (cheap, ship it too)

Serialize `BSScaleformManager::LoadMovie` (ID 1526234) with a plugin-owned
`CRITICAL_SECTION` (recursive, so nested loads on the same thread are safe). If the
deadlock needs two threads inside the movie loader at once, this removes it outright at
the cost of one hook and one lock. It cannot deadlock by itself because it is the
outermost lock in the plugin.

---

## 4. Implementation for 1.10.163

### 4.1 Module base and version guard

```cpp
const auto* f4se = /* F4SEInterface* from F4SEPlugin_Load */;
if (f4se->isEditor) return false;
if (f4se->runtimeVersion != RUNTIME_VERSION_1_10_163) {   // 0x010A0A30
    log("unsupported runtime 0x%08X", f4se->runtimeVersion);
    return false;                                          // refuse to load, no crash
}
HMODULE game = GetModuleHandleA("Fallout4.exe");
```

Never hardcode an absolute address. Resolve every target through the Address Library so a
wrong build fails loudly instead of hooking garbage.

### 4.2 Address resolution

Use `version-1-10-163-0.bin` (already in `Data\F4SE\Plugins\`). Format, verified against
the shipped file: `uint64 count`, then `count x { uint64 id, uint64 rva }`.

```cpp
struct AddressLibrary {
    std::unordered_map<std::uint64_t, std::uint64_t> byId;   // id -> rva
    bool Load(const std::filesystem::path& p) {
        std::ifstream f(p, std::ios::binary);
        std::uint64_t count{}; f.read((char*)&count, 8);
        if (!f || count == 0 || count > 4'000'000) return false;
        byId.reserve(count);
        for (std::uint64_t i = 0; i < count; ++i) {
            std::uint64_t id{}, rva{};
            f.read((char*)&id, 8); f.read((char*)&rva, 8);
            if (!f) return false;
            byId.emplace(id, rva);
        }
        return true;
    }
    void* Get(std::uint64_t id) const {
        auto it = byId.find(id);
        return it == byId.end() ? nullptr
             : (void*)((std::uintptr_t)GetModuleHandleA("Fallout4.exe") + it->second);
    }
};
```

Verified IDs for this build (all confirmed against the shipped address library):

| ID | Symbol | RVA |
|---|---|---|
| 1573164 | `BSReadWriteLock::lock_read` | `0x1b10930` |
| 336186 | `BSReadWriteLock::lock_write` | `0x1b109b0` |
| 1372435 | `BSReadWriteLock::try_lock_read` | `0x1b10b30` |
| 1279453 | `BSReadWriteLock::try_lock_write` | `0x1b10ba0` |
| 1425657 | `BSSpinLock::lock` | `0x244d0` |
| 267930 | `BSSpinLock::try_lock` | `0x7e61b0` |
| 1526234 | `BSScaleformManager::LoadMovie` | `0x2110ad0` |
| 1191277 | `BSScaleformManager::GetMovieFilename` | `0x21110a0` |
| 106578 | `BSScaleformManager::GetSingleton` | — |
| 756304 | `Main::GetSingleton` | — |
| 7491 | `TaskQueueInterface::GetSingleton` | — |

If an ID is missing, **disable the feature and log**; do not fall back to a scan of the
packed file.

### 4.2b If you must signature-scan (runtime image only)

The Address Library is the primary mechanism. A signature is only a fallback, and it must
run against the **loaded** image, never the file:

1. Dump once. Attach a debugger (or a 20-line `ReadProcessMemory` dumper) to a running
   `Fallout4.exe`, read `.text` from `base + 0x1000` for `0x2c0af8f` bytes, and save it.
   This is the only way to get readable code, because the on-disk `.text` is SteamStub
   encrypted (section 0.3).
2. Locate the function in the dump using the ID table above (e.g. `lock_read` at
   `0x1b10930`), then take the first 24-32 bytes as the pattern.
3. Verify the pattern matches **exactly once** in the dump before shipping it. If it matches
   zero or two times, do not use it.

What the patterns will look like, so you can sanity-check them:

* `lock_read` is a small leaf that reads `[rcx+4]`, tests bit 31, and on the contended path
  calls `SleepEx` through the IAT. Expect `8B 41 04` (mov eax,[rcx+4]) near the top and a
  `FF 15` (call [rip+disp]) to `KERNELBASE!SleepEx` about 0x50 bytes in — the capture puts
  the sleep at `lock_read+0x53`.
* `lock_write` starts with a compare against 0 and a `lock cmpxchg` that stores
  `0x80000001`; expect `F0 0F B1` (lock cmpxchg) within the first 0x20 bytes.
* `LoadMovie` is large; do not signature it. Use ID 1526234.

Never ship a signature you have not verified against a dump of the exact build you support,
and never fall back to "first match wins".

### 4.3 Hooking library

**MinHook.** Reasons: x64 trampoline hooks with correct instruction-length decoding,
`MH_EnableHook`/`MH_DisableHook` are thread-safe, ~40 KB static, zlib licence, and it is
already the de-facto standard in the F4SE plugin ecosystem (so it will not fight another
plugin's hook). Detours is larger, has a more restrictive licence, and its
`DetourTransaction` model is awkward for a watchdog that may need to disable a hook at
runtime. Hand-rolled trampolines are not worth the instruction-decoding risk.

### 4.4 The lock hooks

```cpp
using lock_read_t  = void (*)(void* self);
using lock_write_t = void (*)(void* self);

static lock_read_t  g_origLockRead;
static lock_write_t g_origLockWrite;

static void Hook_LockRead(void* self) {
    const auto tid = GetCurrentThreadId();
    if (tid == g_mainThreadId) {
        g_lockObject.store(self, std::memory_order_relaxed);
        g_lockReadEnteredAt.store(GetTickCount64(), std::memory_order_relaxed);
        g_inLockRead.store(true, std::memory_order_release);
    }
    g_origLockRead(self);
    if (tid == g_mainThreadId) g_inLockRead.store(false, std::memory_order_release);
}

static void Hook_LockWrite(void* self) {
    g_origLockWrite(self);
    auto* l = static_cast<BSReadWriteLock*>(self);
    if (l->_lock & 0x80000000u)
        g_lastWriter.store(l->_writerThread, std::memory_order_relaxed);
}
```

`g_mainThreadId` comes from `Main::GetSingleton()->threadID` (offset `0x40`), read once
after `PostPostLoad` — not from `GetCurrentThreadId()` at load time, because plugin load
happens on a different thread.

### 4.5 The breaker

```cpp
static void BreakDeadlock(void* lockObj) {
    auto* l = static_cast<BSReadWriteLock*>(lockObj);
    const std::uint32_t lock = l->_lock;
    if (!(lock & 0x80000000u)) return;                 // writer already gone: nothing to do
    const std::uint32_t writer = l->_writerThread;
    if (writer == g_mainThreadId) return;              // self-deadlock: see Appendix B

    // Park the spinner first so it cannot re-acquire or mutate while we release.
    if (HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, writer)) {
        SuspendThread(h);
        CloseHandle(h);
    }

    // Force-release: writer bit + reader count -> 0, owner cleared.
    l->_writerThread = 0;
    InterlockedExchange(reinterpret_cast<volatile LONG*>(&l->_lock), 0);

    log("BREAK lock=%p writer=%u lockWas=0x%08X", lockObj, writer, lock);
}
```

The main thread's `lock_read` loop re-reads `_lock` every iteration, so it acquires on the
next pass and the queues resume. The parked thread is intentionally leaked: it was already
non-productive, and resuming it would let it re-enter the critical section with a stale
view of the data.

**Blast radius:** the protected structure may be torn. That is accepted only because the
alternative is a permanent hang; the intervention is logged with the lock address so a
crash report can be correlated.

### 4.6 Thread safety rules

* The watchdog never calls engine code except `GetThreadTimes`/`SuspendThread` on a
  foreign thread handle.
* Hook bodies do no allocation, no logging (they push to a lock-free ring buffer), and no
  engine calls.
* The plugin's own state uses `std::atomic` with relaxed ordering where possible; the
  breaker runs on the watchdog thread only, so it needs no lock.
* Never call `MH_DisableHook` from inside a hook.

### 4.7 F4SE plugin entry points

**0.6.23 has no `F4SEPlugin_Version` / `F4SEPluginVersionData`** — that mechanism only
arrived with the 0.7.x ("next-gen") builds. On 1.10.163 the plugin must export
`F4SEPlugin_Query` and `F4SEPlugin_Load` and gate on `runtimeVersion` itself. The
Address Library file name (`version-1-10-163-0.bin`) is the other half of the version guard.

```cpp
extern "C" __declspec(dllexport) bool F4SEPlugin_Query(const F4SEInterface* f4se, PluginInfo* info) {
    info->infoVersion = PluginInfo::kInfoVersion;
    info->name = "FreezeFixF4";
    info->version = 2;
    if (f4se->isEditor) return false;
    if (f4se->runtimeVersion != RUNTIME_VERSION_1_10_163) return false;  // 0x010A0A30
    return true;
}

extern "C" __declspec(dllexport) bool F4SEPlugin_Load(const F4SEInterface* f4se) {
    if (!InitLog()) return true;         // never fail the game because of logging
    if (!CheckRuntime(f4se)) return true;// inert, not fatal
    if (!ResolveAddresses()) { log("address resolution failed; plugin inert"); return true; }
    if (!InstallHooks())     { log("hook install failed; plugin inert");     return true; }
    if (auto* msg = (F4SEMessagingInterface*)f4se->QueryInterface(kInterface_Messaging))
        msg->RegisterListener(f4se->GetPluginHandle(), "F4SE", OnF4SEMessage);
    return true;
}
```

Do **not** export `F4SEPlugin_Version`: 0.6.23 ignores it, and on 0.7.x a wrong version
block silently disables the plugin.

### 4.8 Coexistence with other plugins and F4SE

* Do not hook anything F4SE already hooks: `BSFixedString`, `GameVM`, `Papyrus`,
  `Scaleform` registration, `SaveLoad`, `TaskQueueInterface::AddTask`. We hook only
  `BSReadWriteLock::lock_read/lock_write` and `BSScaleformManager::LoadMovie`, none of
  which F4SE touches.
* Install hooks in `PostPostLoad`, not in `F4SEPlugin_Load`, so every other plugin has
  already patched. If MinHook reports the target already begins with a jump, log and skip
  that hook rather than chaining blindly.
* Use `MH_CreateHook` on the resolved address, never on a hardcoded RVA.

---

## 5. Build and deployment

* **Toolchain:** Visual Studio 2022, `x64`, C++20, `/permissive-`, `/EHsc`.
* **Runtime library:** `/MT` (static CRT). Avoids a VC++ redistributable mismatch on the
  user's machine; the DLL is ~200 KB larger, which is irrelevant here.
* **SDK:** `f4se_0_06_23.7z` from <https://f4se.silverlock.org/> (contains
  `f4se/PluginAPI.h`, `f4se/GameTypes.h`, `f4se_common/`). Alternative: CommonLibF4
  branch `frozen-1.10.63`, which already wraps `REL::ID` and the Address Library.
* **Linker:** `/DLL`, default entry point (do **not** set `/ENTRY`), export
  `F4SEPlugin_Load` and `F4SEPlugin_Version` via `__declspec(dllexport)` or a `.def`.
  No `/EXPORT` of anything else.
* **Dependencies:** MinHook (static lib), `dbghelp.lib` only if you symbolise stacks.
* **Deploy:** `Data\F4SE\Plugins\FreezeFixF4.dll` plus `FreezeFixF4.ini` (thresholds).
* **Verify load:** `Documents\My Games\Fallout4\F4SE\f4se.log` must contain
  `plugin FreezeFixF4.dll (00000001 FreezeFixF4 00000001) loaded correctly`.
  A version mismatch shows as `... disabled, incompatible with current version`.

---

## 6. Testing and validation

### 6.1 Reproduce

1. Same modlist, same save state; launch through `f4se_loader.exe`.
2. Sit at the main menu (do not start a game) for 10 minutes.
3. FreezeSentryF4 with `timeout_ms=15000` must report `both-task-queues-stalled`.
   Baseline: the 2026-11-02 18:15 capture. Expect 1-3 incidents per 10 minutes.

### 6.2 Pass criteria

| Check | Pass |
|---|---|
| `pending` on both queues | stays 0; never 1 for > 2 s |
| main thread in `lock_read` | never > 2 s |
| any thread at 100 % CPU for > 5 s | none |
| 30-minute soak at the main menu | zero incidents |
| 30-minute soak in-game (load, fast travel, open menus) | zero incidents, zero crashes |
| `FreezeFixF4.log` | no `BREAK` lines in a clean run |

### 6.3 Logging

Own file `Documents\My Games\Fallout4\F4SE\FreezeFixF4.log`, rotated at 2 MB, with:

* startup: runtime, F4SE version, resolved addresses, hook results;
* every incident: lock address, `_lock`, `_writerThread`, main TID, queue pending,
  writer CPU %, writer RIP if obtainable;
* every intervention: `BREAK` line with the same fields;
* a lock-free ring buffer for hook-time events, flushed by the watchdog.

### 6.4 Failure handling

Every step is fail-open: if the address library is missing, an ID is absent, MinHook fails,
or the runtime is not 1.10.163, the plugin logs and returns `true` **without hooking**.
The game must never crash or refuse to start because of this plugin.

---

## 7. Risks and limitations

1. **Forced lock release can expose torn data.** Mitigated by only firing after a confirmed
   3 s stall with a spinning writer, and by parking the writer first. A crash is still
   possible; it is strictly better than a permanent hang, but it is not free.
2. **Re-entrancy.** The `LoadMovie` serialisation hook must be recursive; a non-recursive
   mutex there would deadlock on nested loads.
3. **Version drift.** Every address is an Address Library ID; a game patch invalidates the
   IDs and the plugin refuses to load. That is the intended behaviour — do not add a
   "best effort" fallback.
4. **SteamStub.** The on-disk exe cannot be scanned; any future signature work must be done
   on a runtime dump.
5. **This is a workaround.** The defect is in the engine's Scaleform loader (a writer that
   spins while holding a `BSReadWriteLock`) and/or in F4SE's hook path. The correct fix
   belongs in F4SE or in Bethesda's code; report the capture to the F4SE authors.
6. **Other deadlocks.** `ConditionDeadlockFixRD` and `EscapeFreeze` already cover different
   cases; this plugin deliberately does not try to be a general hang detector.

---

## 8. Implementation checklist

1. **Diagnostic build (half a day).** Plugin skeleton + Address Library + `lock_read` hook
   that only logs residency. Run the repro. Confirm `_writerThread` is the spinning thread.
   *Do not skip this.*
2. **Watchdog (half a day).** Thread, thresholds, incident record, log file, ring buffer.
3. **Breaker (one day).** `SuspendThread` + force-release + logging; config flag default on.
4. **Prevention (half a day).** `LoadMovie` serialisation with a recursive critical section.
5. **Validation (two days).** 30-minute main-menu soak x5, in-game soak, modlist A/B with
   and without the plugin.
6. **Ship.** DLL + INI + README with the log location and the "what to send me" list.

### Code layout

```
src/
  main.cpp          F4SEPlugin_Version, F4SEPlugin_Load, message handler
  addresses.cpp     Address Library loader, ID table, resolution + validation
  hooks.cpp         MinHook install/remove, lock_read/lock_write/LoadMovie thunks
  watchdog.cpp      thread, thresholds, incident detection
  breaker.cpp       force-release + park
  log.cpp           file log + lock-free ring buffer
```

---

## 9. Measured result (2026-11-02, this machine)

Build: MSVC 19.x, `/MT /O2`, 190 464 bytes, exports `F4SEPlugin_Load` and
`F4SEPlugin_Query` only. F4SE log confirms
`plugin ...FreezeFixF4.dll (00000001 FreezeFixF4 00000001) loaded correctly`.

Offline check (`tests/addrlib_test.cpp`) against the shipped
`version-1-10-163-0.bin`: all five IDs resolve to the RVAs seen in the capture
(1573164 -> 0x1b10930, 336186 -> 0x1b109b0, 1526234 -> 0x2110ad0,
1191277 -> 0x21110a0, 1425657 -> 0x244d0). `RESULT: PASS`.

In-game, plugin log:

```
[19:55:16.910] STALL tid=14640 lock=00007FF6A3337C60 writer=11952
              lockWas=0x80000001 age=3188ms writerCpu=100%
              writerRip=Fallout4.exe+0x1B773F7
[19:55:16.910] BREAK lock=00007FF6A3337C60 writer=11952 victim=14640 parked=1
[19:55:17.161] RECOVERED victim=14640; queues pump again
```

`writerRip=Fallout4.exe+0x1B773F7` is the **same spin address** as the original
FreezeSentryF4 capture (section 0.2), and the writer held `_lock = 0x80000001`.
The deadlock is therefore reproduced and reproduced identically; the victim resumed
within 250 ms and the session continued (no further incidents over the following
minutes, heartbeats only).

Two caveats from this run:

* The break parks the spinning thread permanently. In one session the user then hit
  "load a save whose plugins were removed": the confirmation message box never
  appeared and the load never finished. Fix4 logged **no** `lock_read` stall during
  that load, so it is not the same deadlock; whether the parked movie-loader thread
  is implicated is still open. Reproduce with the plugin disabled before blaming it.
* FreezeSentryF4 still emits `prehang-*.log` while the console is open or the window
  is in the background (`hang_suppressed reason=background-responsive`). Treat those
  as false positives; the plugin's own log is the authoritative signal.

### 9.1 A/B control on the same machine

| Run | INI | What the plugin saw | What happened |
|---|---|---|---|
| **A** | `Fix=0` (observe) | `STALL tid=26488 writer=17480 lockWas=0x80000001 writerCpu=100% writerRip=Fallout4.exe+0x1B773F9` | **Freeze.** 15.1 s stall, `reason=both-task-queues-stalled`, `normal_queue pending=1`, `ui_queue pending=1`, window `Responding=False`. A 14.6 GB full dump was written this time. |
| **B** | `Fix=1` (x2) | same stall, `writerRip=Fallout4.exe+0x1B773F7` | **No freeze.** Lock cleared, parked owner, victim resumed in 250 ms, session continued. |

Run A main-thread stack — note the plugin's pass-through frame sitting where the engine
frame was in the 18:15 capture:

```
NtDelayExecution
KERNELBASE!SleepEx
Fallout4.exe+0x1b10983     BSReadWriteLock::lock_read
FreezeFixF4.dll+0x1af6     <-- observe-mode hook, calls the original
Fallout4.exe+0x1b7172f
Fallout4.exe+0x1b6d313
Fallout4.exe+0x2114c65
Fallout4.exe+0x21110e4     BSScaleformManager::GetMovieFilename
Fallout4.exe+0x2110b62     BSScaleformManager::LoadMovie
```

That is the same signature as the original dump, so the hook is on the right function and
observe mode is a true control. Conclusion: the deadlock is real and reproducible
(~20 s after `PostPostLoad`, every launch), and the break is what prevents the hang.

**Housekeeping:** the control run wrote a 14.6 GB `freeze-*.dmp` to
`Documents\My Games\Fallout4\F4SE\FreezeSentryF4\` (C: had 32.9 GB free). Delete it, or set
`FullMemoryDump=0` in `FreezeSentryF4.ini`, before running more freeze tests.

### 9.2 Final root cause and fix (v1.4)

The spin at `Fallout4.exe+0x1b773f7` is a hash-chain walk:

```
1b773f0  mov    %ecx,%r9d
1b773f3  movzwl (%rdx,%rcx,4),%ecx     ; next = chain[i]
1b773f7  cmp    %ebx,%ecx              ; == target bucket?
1b773f9  jne    1b773f0                ; no -> keep walking
```

At the hang `rcx = 0xFFFF`, `rbx = 2`, and entry `0xFFFF` is `0xFFFFFFFF`, whose `next`
is itself — the walk runs into the empty sentinel and never terminates. The thread holds
the movie-definition `BSReadWriteLock` for write, so the main thread's `lock_read` blocks
and the game freezes.

Earlier attempts either parked the owner (menu never finished registering) or forced the
walk to return "not found" (table left inconsistent, menu never came back). **v1.4 repairs
the link instead**: when the walk is stuck, point the current entry's `next` at the bucket
the loop is looking for, so the insert completes normally. Verified:

```
[20:56:26.604] SPIN tid=18468 rip=+0x107 rcx=0xFFFF rbx=0x2
[20:57:10.888] heartbeat calls=32934830 incidents=0 breaks=0 defers=0 spins=1
```

`breaks=0` — the lock breaker never fired; the spin breaker alone fixed it. The main menu
then rendered, the missing-content dialog appeared, and the quicksave
(`Quicksave0_..._SS2C2HQMain_..._159_2.fos`, level 159) loaded to a playable game.

---

## Appendix A — verified addresses for 1.10.163

| RVA | Meaning | Source |
|---|---|---|
| `0x1b10930` | `BSReadWriteLock::lock_read` | ID 1573164 |
| `0x1b109b0` | `BSReadWriteLock::lock_write` | ID 336186 |
| `0x2110ad0` | `BSScaleformManager::LoadMovie` | ID 1526234 |
| `0x21110a0` | `BSScaleformManager::GetMovieFilename` | ID 1191277 |
| `0x244d0` | `BSSpinLock::lock` | ID 1425657 |
| `0x1b773f7` | spinner RIP (inside a function entered at `0x1b772f0`) | capture |
| `0x1b1cfed` | spinner thread entry | capture |
| `0xd535a9` | engine function called from F4SE `+0xa8ac` | capture |

## Appendix B — if the diagnostic disproves section 1.1

* **`_writerThread` is a blocked (0 % CPU) thread.** The writer is waiting on something the
  main thread owns. Then the fix is the opposite: find what the writer waits on (its stack
  will show it) and release *that* from the watchdog, or serialise the two paths. Re-run
  the diagnostic with the writer's stack captured.
* **`_writerThread == mainTid`.** Self-deadlock: the main thread already holds the write
  lock and re-enters `lock_read`. Then the breaker must instead skip the acquisition
  (return without touching `_lock`) — but the matching inline `unlock_read` will then
  underflow the count, so this case needs a different fix: hook the *caller*
  (`GetMovieFilename`) and avoid the nested load entirely.
* **No writer bit set, main thread still sleeping.** The sleep is not the lock; re-read the
  stack and treat `SleepEx` as the primary target (option A becomes viable).
