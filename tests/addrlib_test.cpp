// Offline check of the address-library parser used by FreezeFixF4.
// Verifies the shipped version-1-10-163-0.bin maps the IDs the plugin relies on
// to the RVAs observed in the FreezeSentryF4 capture.
#include <cstdint>
#include <cstdio>
#include <unordered_map>

int main(int argc, char** argv) {
    if (argc < 2) { std::printf("usage: addrlib_test <version-1-10-163-0.bin>\n"); return 2; }
    FILE* f = nullptr;
    if (fopen_s(&f, argv[1], "rb") != 0 || !f) { std::printf("FAIL open\n"); return 1; }

    std::uint64_t count = 0;
    if (std::fread(&count, sizeof(count), 1, f) != 1 || count == 0 || count > 4000000) {
        std::printf("FAIL header\n"); return 1;
    }
    std::unordered_map<std::uint64_t, std::uint64_t> ids;
    ids.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        std::uint64_t id = 0, rva = 0;
        if (std::fread(&id, sizeof(id), 1, f) != 1 || std::fread(&rva, sizeof(rva), 1, f) != 1) {
            std::printf("FAIL body at %llu\n", static_cast<unsigned long long>(i)); return 1;
        }
        ids.emplace(id, rva);
    }
    std::fclose(f);
    std::printf("entries=%zu\n", ids.size());

    struct Expect { std::uint64_t id; std::uint64_t rva; const char* name; };
    const Expect expected[] = {
        { 1573164, 0x1b10930, "BSReadWriteLock::lock_read" },
        { 336186,  0x1b109b0, "BSReadWriteLock::lock_write" },
        { 1526234, 0x2110ad0, "BSScaleformManager::LoadMovie" },
        { 1191277, 0x21110a0, "BSScaleformManager::GetMovieFilename" },
        { 1425657, 0x244d0,   "BSSpinLock::lock" },
    };
    int failures = 0;
    for (const auto& e : expected) {
        const auto it = ids.find(e.id);
        const bool ok = it != ids.end() && it->second == e.rva;
        std::printf("%s id=%llu %s -> 0x%llx (want 0x%llx)\n", ok ? "ok  " : "FAIL",
                    static_cast<unsigned long long>(e.id), e.name,
                    static_cast<unsigned long long>(it == ids.end() ? 0 : it->second),
                    static_cast<unsigned long long>(e.rva));
        if (!ok) ++failures;
    }
    std::printf(failures ? "RESULT: FAIL (%d)\n" : "RESULT: PASS\n", failures);
    return failures ? 1 : 0;
}
