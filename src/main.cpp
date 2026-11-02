// FreezeFixF4 - F4SE plugin for Fallout 4 1.10.163
//
// Two failure modes are handled:
//  1. A thread spins forever in the engine's hash-chain walk (0x1b773f7) while
//     holding a BSReadWriteLock for write. The walk runs off the end of the chain
//     into the 0xFFFF sentinel, whose "next" is itself, so it never terminates.
//     We force the loop to exit by setting RBX (the compared value) to 0xFFFF.
//  2. If a reader is still stuck on that lock afterwards, we clear the writer bit
//     so the game can continue (last resort; leaves the owner parked).

#include <windows.h>
#include <tlhelp32.h>
#include <fcntl.h>
#include <io.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <string>
#include <unordered_map>

typedef unsigned int       UInt32;
typedef unsigned long long UInt64;
typedef unsigned char      UInt8;

#include "f4se/PluginAPI.h"
#include "f4se/f4se_version.h"
#include "minhook/include/MinHook.h"

namespace {

constexpr UInt32 kRuntimeVersion = RUNTIME_VERSION_1_10_163;  // 0x010A0A30
constexpr std::uint64_t kLockReadId = 1573164;                // BSReadWriteLock::lock_read
constexpr std::uint64_t kHashInsertId = 1541972;              // function containing the chain walk
constexpr std::uint32_t kSpinLo = 0xE0;                       // loop offsets from that entry
constexpr std::uint32_t kSpinHi = 0x10A;
constexpr std::uint32_t kSpinExit = 0x156;                    // "not found" epilogue (xor al,al; ret)

struct Config {
    bool  fix = true;
    DWORD breakMs = 3000;
    DWORD pollMs = 250;
    DWORD writerCpuMin = 40;
    DWORD spinHits = 4;
};
Config g_cfg;

FILE*   g_log = nullptr;
SRWLOCK g_logLock = SRWLOCK_INIT;
wchar_t g_dllDir[MAX_PATH] = {};
bool    g_installed = false;
PluginHandle g_handle = kPluginHandle_Invalid;
F4SEMessagingInterface* g_messaging = nullptr;

void Log(const char* fmt, ...) {
    if (!g_log) return;
    AcquireSRWLockExclusive(&g_logLock);
    SYSTEMTIME st{};
    GetLocalTime(&st);
    std::fprintf(g_log, "[%02u:%02u:%02u.%03u] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(g_log, fmt, ap);
    va_end(ap);
    std::fputc('\n', g_log);
    std::fflush(g_log);
    ReleaseSRWLockExclusive(&g_logLock);
}

void InitPaths() {
    HMODULE self = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(&InitPaths), &self))
        return;
    wchar_t path[MAX_PATH] = {};
    const DWORD n = GetModuleFileNameW(self, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return;
    wchar_t* slash = wcsrchr(path, L'\\');
    if (!slash) return;
    *slash = 0;
    wcsncpy_s(g_dllDir, path, _TRUNCATE);
}

void OpenLog() {
    if (!g_dllDir[0]) return;
    wchar_t path[MAX_PATH] = {};
    _snwprintf_s(path, _TRUNCATE, L"%s\\FreezeFixF4.log", g_dllDir);
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        g_log = nullptr;
        return;
    }
    const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(h), _O_APPEND);
    if (fd == -1) {
        CloseHandle(h);
        g_log = nullptr;
        return;
    }
    g_log = _fdopen(fd, "a");
    if (!g_log) _close(fd);
}

void ReadConfig() {
    wchar_t path[MAX_PATH] = {};
    _snwprintf_s(path, _TRUNCATE, L"%s\\FreezeFixF4.ini", g_dllDir);
    g_cfg.fix          = GetPrivateProfileIntW(L"FreezeFixF4", L"Fix", 1, path) != 0;
    g_cfg.breakMs      = static_cast<DWORD>(GetPrivateProfileIntW(L"FreezeFixF4", L"BreakMilliseconds", 3000, path));
    g_cfg.pollMs       = static_cast<DWORD>(GetPrivateProfileIntW(L"FreezeFixF4", L"PollMilliseconds", 250, path));
    g_cfg.writerCpuMin = static_cast<DWORD>(GetPrivateProfileIntW(L"FreezeFixF4", L"WriterCpuPercent", 40, path));
    g_cfg.spinHits     = static_cast<DWORD>(GetPrivateProfileIntW(L"FreezeFixF4", L"SpinSamples", 4, path));
    if (g_cfg.breakMs < 1000)   g_cfg.breakMs = 1000;
    if (g_cfg.breakMs > 60000)  g_cfg.breakMs = 60000;
    if (g_cfg.pollMs < 50)      g_cfg.pollMs = 50;
    if (g_cfg.pollMs > 5000)    g_cfg.pollMs = 5000;
    if (g_cfg.writerCpuMin > 100) g_cfg.writerCpuMin = 100;
    if (g_cfg.spinHits < 2)     g_cfg.spinHits = 2;
    if (g_cfg.spinHits > 40)    g_cfg.spinHits = 40;
}

// ---- address library -----------------------------------------------------

std::unordered_map<std::uint64_t, std::uint64_t> g_ids;

bool LoadAddressLibrary(const wchar_t* path) {
    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"rb") != 0 || !f) return false;
    std::uint64_t count = 0;
    if (std::fread(&count, sizeof(count), 1, f) != 1 || count == 0 || count > 4000000) {
        std::fclose(f);
        return false;
    }
    g_ids.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        std::uint64_t id = 0, rva = 0;
        if (std::fread(&id, sizeof(id), 1, f) != 1 || std::fread(&rva, sizeof(rva), 1, f) != 1) {
            std::fclose(f);
            return false;
        }
        g_ids.emplace(id, rva);
    }
    std::fclose(f);
    return true;
}

void* Resolve(std::uint64_t id) {
    const auto it = g_ids.find(id);
    if (it == g_ids.end()) return nullptr;
    return reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr)) + it->second);
}

// ---- lock residency tracking ---------------------------------------------

struct Slot {
    std::atomic<DWORD>    tid{0};
    std::atomic<void*>    obj{nullptr};
    std::atomic<uint64_t> since{0};
};
constexpr std::size_t kSlots = 512;
Slot g_slots[kSlots];

std::atomic<std::uint64_t> g_calls{0};
std::atomic<std::uint64_t> g_incidents{0};
std::atomic<std::uint64_t> g_breaks{0};
std::atomic<std::uint64_t> g_defers{0};
std::atomic<std::uint64_t> g_spins{0};
std::atomic<bool>          g_armed{true};
std::atomic<DWORD>         g_brokenVictim{0};
void*                      g_spinEntry = nullptr;

typedef void (*LockReadFn)(void*);
LockReadFn g_origLockRead = nullptr;

void HookLockRead(void* self) {
    const DWORD tid = GetCurrentThreadId();
    Slot& s = g_slots[((tid * 2654435761u) >> 23) & (kSlots - 1)];
    s.obj.store(self, std::memory_order_relaxed);
    s.since.store(GetTickCount64(), std::memory_order_relaxed);
    s.tid.store(tid, std::memory_order_release);
    g_calls.fetch_add(1, std::memory_order_relaxed);

    g_origLockRead(self);

    s.tid.store(0, std::memory_order_release);
}

// ---- diagnostics ---------------------------------------------------------

std::uint64_t ThreadCpu100ns(HANDLE h) {
    FILETIME c{}, e{}, k{}, u{};
    if (!GetThreadTimes(h, &c, &e, &k, &u)) return 0;
    return (static_cast<std::uint64_t>(u.dwHighDateTime) << 32 | u.dwLowDateTime) +
           (static_cast<std::uint64_t>(k.dwHighDateTime) << 32 | k.dwLowDateTime);
}

DWORD WriterCpuPercent(DWORD tid, DWORD windowMs) {
    HANDLE h = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!h) return 0xFFFFFFFF;
    const std::uint64_t cpu0 = ThreadCpu100ns(h);
    const std::uint64_t wall0 = GetTickCount64();
    Sleep(windowMs);
    const std::uint64_t cpu1 = ThreadCpu100ns(h);
    const std::uint64_t wall1 = GetTickCount64();
    CloseHandle(h);
    if (wall1 <= wall0) return 0xFFFFFFFF;
    const std::uint64_t cpu = cpu1 > cpu0 ? cpu1 - cpu0 : 0;
    const std::uint64_t wall100ns = (wall1 - wall0) * 10000ULL;
    if (!wall100ns) return 0xFFFFFFFF;
    return static_cast<DWORD>(100ULL * cpu / wall100ns);
}

// ---- spin breaker --------------------------------------------------------

struct SpinSlot {
    DWORD     tid = 0;
    ULONGLONG cpu = 0;
    ULONGLONG wall = 0;
    int       hits = 0;
};
SpinSlot g_spin[128];

void CheckSpins(void* entry) {
    if (!entry) return;
    const auto lo = reinterpret_cast<std::uintptr_t>(entry) + kSpinLo;
    const auto hi = reinterpret_cast<std::uintptr_t>(entry) + kSpinHi;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    const DWORD pid = GetCurrentProcessId();
    const DWORD self = GetCurrentThreadId();
    const ULONGLONG now = GetTickCount64();
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) continue;
            const DWORD tid = te.th32ThreadID;
            HANDLE h = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                                  FALSE, tid);
            if (!h) continue;
            const ULONGLONG cpu = ThreadCpu100ns(h);
            SpinSlot* slot = nullptr;
            for (auto& s : g_spin) if (s.tid == tid) { slot = &s; break; }
            if (!slot) for (auto& s : g_spin) if (s.tid == 0) { slot = &s; slot->tid = tid; break; }
            if (!slot) { CloseHandle(h); continue; }

            const ULONGLONG dcpu = cpu > slot->cpu ? cpu - slot->cpu : 0;
            const ULONGLONG dwall = now > slot->wall ? now - slot->wall : 0;
            slot->cpu = cpu;
            slot->wall = now;
            const bool busy = dwall > 0 && dcpu >= dwall * 4000ULL;  // >= 40% of one core
            if (!busy) { slot->hits = 0; CloseHandle(h); continue; }

            SuspendThread(h);
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            if (GetThreadContext(h, &ctx)) {
                if (ctx.Rip >= lo && ctx.Rip < hi) {
                    if (++slot->hits >= static_cast<int>(g_cfg.spinHits)) {
                        Log("SPIN tid=%lu rip=+0x%llX rcx=0x%llX rbx=0x%llX -> returning not-found",
                            tid, static_cast<unsigned long long>(ctx.Rip - reinterpret_cast<std::uintptr_t>(entry)),
                            static_cast<unsigned long long>(ctx.Rcx), static_cast<unsigned long long>(ctx.Rbx));
                        // Terminate the walk where it is stuck: point the entry's "next" at the
                        // bucket the loop is looking for, so the insert completes normally.
                        auto* next = reinterpret_cast<volatile std::uint16_t*>(ctx.Rdx + ctx.Rcx * 4);
                        *next = static_cast<std::uint16_t>(ctx.Rbx);
                        SetThreadContext(h, &ctx);
                        g_spins.fetch_add(1, std::memory_order_relaxed);
                        slot->hits = 0;
                    }
                } else {
                    slot->hits = 0;
                }
            }
            ResumeThread(h);
            CloseHandle(h);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

// ---- lock breaker (fallback) ---------------------------------------------

// Inspect the write-lock owner. If it is stuck in the hash-chain walk, repair the link
// so the insert finishes and the lock is released normally. Returns true if repaired.
bool CheckAndRepairWriter(DWORD tid, std::uintptr_t& ripOut) {
    ripOut = 0;
    HANDLE h = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                          FALSE, tid);
    if (!h) return false;
    SuspendThread(h);
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    bool repaired = false;
    if (GetThreadContext(h, &ctx)) {
        ripOut = ctx.Rip;
        const auto entry = reinterpret_cast<std::uintptr_t>(g_spinEntry);
        if (g_spinEntry && ctx.Rip >= entry + kSpinLo && ctx.Rip < entry + kSpinHi) {
            auto* next = reinterpret_cast<volatile std::uint16_t*>(ctx.Rdx + ctx.Rcx * 4);
            *next = static_cast<std::uint16_t>(ctx.Rbx);
            repaired = true;
            g_spins.fetch_add(1, std::memory_order_relaxed);
        }
    }
    ResumeThread(h);
    CloseHandle(h);
    return repaired;
}

void HandleStall(DWORD victim, void* obj, std::uint64_t ageMs) {
    auto* writerField = static_cast<volatile LONG*>(obj);
    auto* lockField   = writerField + 1;

    const LONG lockValue = *lockField;
    const LONG writer    = *writerField;
    if (!(lockValue & 0x80000000L)) {
        Log("STALL tid=%lu lock=%p no-writer-bit lock=0x%08X (not a lock stall)",
            victim, obj, static_cast<unsigned>(lockValue));
        return;
    }
    if (writer == static_cast<LONG>(victim)) {
        Log("STALL tid=%lu lock=%p self-deadlock", victim, obj);
        return;
    }

    std::uintptr_t writerRip = 0;
    const bool repaired = g_cfg.fix && CheckAndRepairWriter(static_cast<DWORD>(writer), writerRip);

    const DWORD cpu = repaired ? 0 : WriterCpuPercent(static_cast<DWORD>(writer), 500);
    Log("STALL tid=%lu lock=%p writer=%ld lockWas=0x%08X age=%llums writerRip=0x%llX writerCpu=%ld%% repaired=%d",
        victim, obj, writer, static_cast<unsigned>(lockValue),
        static_cast<unsigned long long>(ageMs),
        static_cast<unsigned long long>(writerRip),
        cpu == 0xFFFFFFFF ? -1L : static_cast<long>(cpu), repaired ? 1 : 0);

    if (repaired) return;      // the owner will finish and release the lock itself
    if (!g_cfg.fix) return;
    if (cpu == 0xFFFFFFFF || cpu < g_cfg.writerCpuMin) {
        g_defers.fetch_add(1, std::memory_order_relaxed);
        Log("DEFER owner is not spinning (cpu=%ld%%); leaving the lock alone",
            cpu == 0xFFFFFFFF ? -1L : static_cast<long>(cpu));
        return;
    }

    HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, static_cast<DWORD>(writer));
    if (h) {
        SuspendThread(h);
        CloseHandle(h);
    }
    *writerField = 0;
    InterlockedExchange(lockField, 0);
    g_breaks.fetch_add(1, std::memory_order_relaxed);
    g_brokenVictim.store(victim, std::memory_order_relaxed);
    Log("BREAK lock=%p writer=%ld victim=%lu parked=%d", obj, writer, victim, h ? 1 : 0);
}

DWORD WINAPI Watchdog(LPVOID param) {
    void* spinEntry = param;
    std::uint64_t lastBeat = GetTickCount64();
    unsigned tick = 0;
    for (;;) {
        Sleep(g_cfg.pollMs);
        const std::uint64_t now = GetTickCount64();

        if (g_cfg.fix && (++tick % 4) == 0) CheckSpins(spinEntry);

        bool anyVictim = false;
        for (std::size_t i = 0; i < kSlots; ++i) {
            const DWORD tid = g_slots[i].tid.load(std::memory_order_acquire);
            if (!tid) continue;
            anyVictim = true;
            const std::uint64_t age = now - g_slots[i].since.load(std::memory_order_acquire);
            if (age < g_cfg.breakMs) continue;
            if (!g_armed.exchange(false)) continue;

            void* obj = g_slots[i].obj.load(std::memory_order_relaxed);
            g_incidents.fetch_add(1, std::memory_order_relaxed);
            HandleStall(tid, obj, age);
        }

        if (!anyVictim) {
            const DWORD broken = g_brokenVictim.exchange(0);
            if (broken) Log("RECOVERED victim=%lu; queues pump again", broken);
            g_armed.store(true, std::memory_order_release);
        }

        if (now - lastBeat >= 60000) {
            lastBeat = now;
            Log("heartbeat calls=%llu incidents=%llu breaks=%llu defers=%llu spins=%llu",
                static_cast<unsigned long long>(g_calls.load()),
                static_cast<unsigned long long>(g_incidents.load()),
                static_cast<unsigned long long>(g_breaks.load()),
                static_cast<unsigned long long>(g_defers.load()),
                static_cast<unsigned long long>(g_spins.load()));
        }
    }
}

void Install() {
    if (g_installed) return;
    g_installed = true;

    wchar_t addrLib[MAX_PATH] = {};
    _snwprintf_s(addrLib, _TRUNCATE, L"%s\\version-1-10-163-0.bin", g_dllDir);
    if (!LoadAddressLibrary(addrLib)) {
        Log("address library not found at %ls; plugin inert", addrLib);
        return;
    }
    Log("address library entries=%zu", g_ids.size());

    void* lockRead = Resolve(kLockReadId);
    void* spinEntry = Resolve(kHashInsertId);
    g_spinEntry = spinEntry;
    if (!lockRead) {
        Log("lock_read id missing; plugin inert");
        return;
    }
    Log("lock_read=%p spinEntry=%p", lockRead, spinEntry);

    if (MH_Initialize() != MH_OK) {
        Log("MH_Initialize failed; plugin inert");
        return;
    }
    if (MH_CreateHook(lockRead, &HookLockRead, reinterpret_cast<void**>(&g_origLockRead)) != MH_OK) {
        Log("MH_CreateHook failed; plugin inert");
        return;
    }
    if (MH_EnableHook(lockRead) != MH_OK) {
        Log("MH_EnableHook failed; plugin inert");
        return;
    }
    Log("lock_read hook enabled");

    HANDLE thread = CreateThread(nullptr, 0, &Watchdog, spinEntry, 0, nullptr);
    if (thread) CloseHandle(thread);

    Log("watchdog started mode=%s breakMs=%lu pollMs=%lu writerCpuMin=%lu%% spinSamples=%lu",
        g_cfg.fix ? "fix" : "observe", g_cfg.breakMs, g_cfg.pollMs, g_cfg.writerCpuMin, g_cfg.spinHits);
}

void OnF4SEMessage(F4SEMessagingInterface::Message* msg) {
    if (!msg) return;
    if (msg->type == F4SEMessagingInterface::kMessage_PostPostLoad) Install();
}

}  // namespace

extern "C" __declspec(dllexport) bool F4SEPlugin_Query(const F4SEInterface* f4se, PluginInfo* info) {
    info->infoVersion = PluginInfo::kInfoVersion;
    info->name = "FreezeFixF4";
    info->version = 3;
    if (f4se->isEditor) return false;
    if (f4se->runtimeVersion != kRuntimeVersion) return false;
    g_handle = f4se->GetPluginHandle();
    return true;
}

extern "C" __declspec(dllexport) bool F4SEPlugin_Load(const F4SEInterface* f4se) {
    InitPaths();
    OpenLog();
    ReadConfig();
    Log("FreezeFixF4 1.2.0 runtime=0x%08X f4se=0x%08X dir=%ls",
        f4se->runtimeVersion, f4se->f4seVersion, g_dllDir);

    g_messaging = static_cast<F4SEMessagingInterface*>(f4se->QueryInterface(kInterface_Messaging));
    if (!g_messaging || !g_messaging->RegisterListener(g_handle, "F4SE", &OnF4SEMessage)) {
        Log("messaging registration failed; plugin inert");
        return true;
    }
    Log("registered for F4SE messages");
    return true;
}
