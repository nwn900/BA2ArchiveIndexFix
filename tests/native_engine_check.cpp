// Optional Linux x86-64 differential test; no game machine code is bundled.
// The Python driver verifies user-supplied bytes before running this process.
#include "archive_index.h"

#ifdef NDEBUG
#error Native validation requires assertions to remain enabled.
#endif
#include <sys/mman.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <stdexcept>
#include <vector>
namespace a=freezefix::archive;
struct NativeTable {
    std::uint64_t unknown=0;
    a::Entry* entries=nullptr;
    std::uint32_t capacity=0, mask=0, available=0, lastFree=0;
};
struct alignas(16) NativeIndex {
    std::array<std::byte,0x10> prefix{};
    NativeTable table{};
    std::array<std::byte,0x1000> arrays{};
    a::Key keys[256]{};
    std::uint32_t count=0;
};
static_assert(sizeof(NativeTable)==0x20);
static_assert(offsetof(NativeIndex,table)==0x10);
static_assert(offsetof(NativeIndex,keys)==0x1030);
static_assert(offsetof(NativeIndex,count)==0x1c30);
struct Code {
    void* memory=nullptr;
    std::size_t length=0;
    Code(const char* path,std::size_t bytes) {
        std::ifstream input(path,std::ios::binary);
        if(!input) throw std::runtime_error("open byte fixture");
        length=static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
        memory=mmap(nullptr,length,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(memory==MAP_FAILED) throw std::runtime_error("mmap");
        input.read(static_cast<char*>(memory),static_cast<std::streamsize>(bytes));
        if(static_cast<std::size_t>(input.gcount())!=bytes) throw std::runtime_error("short fixture");
        if(mprotect(memory,length,PROT_READ|PROT_EXEC)!=0) throw std::runtime_error("mprotect");
    }
    ~Code() { if(memory && memory!=MAP_FAILED) munmap(memory,length); }
};
using InsertFn=bool(__attribute__((ms_abi)) *)(NativeTable*,std::uint32_t,a::Key**);
using FindFn=std::uint32_t(__attribute__((ms_abi)) *)(NativeIndex*,const a::Key*);

// These counterexamples exercise unchanged native instructions with the split
// key-storage convention described by Daytripper's source. They do not load a
// Daytripper DLL, establish its C++ vector ABI, or reproduce a user's game state.
std::atomic<std::uintptr_t> expected_spin_begin{0}, expected_spin_end{0};
static_assert(std::atomic<std::uintptr_t>::is_always_lock_free);

void CheckSpinInstruction(int, siginfo_t*, void* context) {
    const auto* state=static_cast<const ucontext_t*>(context);
    const auto ip=static_cast<std::uintptr_t>(state->uc_mcontext.gregs[REG_RIP]);
    const bool in_predecessor_walk=ip>=expected_spin_begin.load(std::memory_order_relaxed) &&
                                   ip<expected_spin_end.load(std::memory_order_relaxed);
    _exit(in_predecessor_walk ? 0 : 20);
}

void SplitStorageCounterexamples(InsertFn insert, FindFn find) {
    // Slot 255 contains an opaque pointer, rather than its original twelve-byte
    // key. Page alignment makes its low word distinct from the chosen real key.
    // No instruction in these tests dereferences this stand-in vector pointer.
    alignas(4096) std::array<std::byte,4096> vector_object{};
    const auto vector_pointer=reinterpret_cast<std::uintptr_t>(vector_object.data());
    {
        constexpr std::uint32_t capacity=1024;
        std::vector<a::Entry> slots(capacity);
        NativeIndex index;
        index.table={0,slots.data(),capacity,capacity-1,capacity,capacity-1};
        std::array<a::Key,256> flattened{};
        auto* fixed=index.keys;
        for(std::uint32_t i=0;i<255;++i) {
            index.keys[i]={i+1,i+100,17};
            flattened[i]=index.keys[i];
            assert(insert(&index.table,i,&fixed));
            ++index.count;
        }
        const a::Key extended_key{1,0xABCD,0x1234};
        flattened[255]=extended_key;
        auto* flat=flattened.data();
        assert(insert(&index.table,255,&flat));
        ++index.count;
        index.keys[255]={static_cast<std::uint32_t>(vector_pointer),
                         static_cast<std::uint32_t>(vector_pointer>>32),0};
        assert(slots[1].index==0 && slots[1].next!=a::kEnd);
        assert(slots[slots[1].next].index==255);
        assert(a::Equal(flattened[255],extended_key));
        // Daytripper's first-key accessor returns the native address for member
        // zero. Its unpatched collision path then reads native slot 255, so the
        // original routine is equivalent for this particular lookup fixture.
        const auto found=find(&index,&extended_key);
        if(found!=index.count) std::fprintf(stderr,"split lookup found=%u count=%u head=%u next=%u tail=%u native255=%08x,%08x,%08x true=%08x,%08x,%08x\n",found,index.count,slots[1].index,slots[1].next,slots[slots[1].next].index,index.keys[255].word0,index.keys[255].word1,index.keys[255].word2,extended_key.word0,extended_key.word1,extended_key.word2);
        assert(found==index.count);
        std::puts("PASS: a table built from true extended keys still loses an overflow lookup through the fixed-array collision path");
    }
    {
        constexpr std::uint32_t capacity=65536;
        std::vector<a::Entry> slots(capacity);
        NativeIndex index;
        index.table={0,slots.data(),capacity,capacity-1,capacity,capacity-1};
        auto* fixed=index.keys;
        for(std::uint32_t i=0;i<255;++i) {
            index.keys[i]={i,i+100,17};
            assert(insert(&index.table,i,&fixed));
            ++index.count;
        }
        index.keys[255]={static_cast<std::uint32_t>(vector_pointer),
                         static_cast<std::uint32_t>(vector_pointer>>32),0};
        assert(insert(&index.table,255,&fixed));
        ++index.count;
        // Native key[256].word0 aliases the mutable count at Index+0x1C30.
        static_assert(offsetof(NativeIndex,keys)+256*sizeof(a::Key)==offsetof(NativeIndex,count));
        assert(index.count==256);
        assert(insert(&index.table,256,&fixed));
        assert(slots[256].index==256);
        ++index.count; // The native interpretation of member 256's hash changes.
        // Keep key[257]'s one accessed word inside explicitly allocated object
        // storage (tail padding). This is controlled fixture data, not an OOB
        // C++ array access or a claim about a user's surrounding memory.
        constexpr std::size_t next_word=offsetof(NativeIndex,keys)+257*sizeof(a::Key);
        static_assert(next_word+sizeof(std::uint32_t)<=sizeof(NativeIndex));
        const std::uint32_t incoming_hash=256;
        std::memcpy(reinterpret_cast<std::byte*>(&index)+next_word,&incoming_hash,sizeof(incoming_hash));
        assert(slots[257].next==a::kEnd && slots[257].index==a::kEnd);
        assert(slots[a::kEnd].next==a::kEnd && slots[a::kEnd].index==a::kEnd);

        // Run the expected infinite loop only in an expendable child. The alarm
        // checks that execution is in insert+0x100..0x10A (RVA 0x1B773F0..FA),
        // then exits. A timeout anywhere else, an early return, or a crash fails.
        const auto code=reinterpret_cast<std::uintptr_t>(insert);
        expected_spin_begin.store(code+0x100,std::memory_order_relaxed);
        expected_spin_end.store(code+0x10B,std::memory_order_relaxed);
        const pid_t child=fork();
        if(child<0) throw std::runtime_error("fork spin counterexample");
        if(child==0) {
            struct sigaction action{};
            action.sa_sigaction=&CheckSpinInstruction;
            action.sa_flags=SA_SIGINFO;
            sigemptyset(&action.sa_mask);
            if(sigaction(SIGALRM,&action,nullptr)!=0) _exit(21);
            sigset_t alarm_signal;
            sigemptyset(&alarm_signal);
            sigaddset(&alarm_signal,SIGALRM);
            // Do not inherit a blocked timeout signal from the invoking shell.
            if(sigprocmask(SIG_UNBLOCK,&alarm_signal,nullptr)!=0) _exit(23);
            alarm(2);
            (void)insert(&index.table,257,&fixed);
            _exit(22);
        }
        int status=0;
        pid_t waited=0;
        do { waited=waitpid(child,&status,0); } while(waited<0 && errno==EINTR);
        assert(waited==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
        std::puts("PASS: fixed-array count alias reproduces the native predecessor spin at insert+0x100..0x10A in a bounded child");
    }
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fputs("Use tests/run_native_validation.py to verify and provide the two routine fixtures.\n", stderr);
        return 2;
    }
    Code insertCode(argv[1],0x16a);
    Code findCode(argv[2],0xfe);
    auto insert=reinterpret_cast<InsertFn>(insertCode.memory);
    auto find=reinterpret_cast<FindFn>(findCode.memory);
    SplitStorageCounterexamples(insert,find);
    std::mt19937 rng(0xF4F4);
    unsigned cases=0,lookups=0;
    for(auto capacity: {2u,4u,8u,16u,64u,512u,32768u,65536u}) {
        for(unsigned trial=0;trial<24;++trial) {
            const std::uint32_t n=std::min(capacity-1,1u+static_cast<std::uint32_t>(rng()%255u));
            std::vector<a::Entry> slots(capacity),out(capacity);
            NativeIndex index;
            index.table={0,slots.data(),capacity,capacity-1,capacity,capacity-1};
            for(std::uint32_t i=0;i<n+1;++i) {
                index.keys[i]={trial%3==0?1u:static_cast<std::uint32_t>(rng()),i,trial};
            }
            if(capacity==65536 && trial%4==0) for(std::uint32_t i=0;i<n+1;++i) index.keys[i].word0=0xffff;
            auto* keyBase=index.keys;
            for(std::uint32_t i=0;i<n;++i) { assert(insert(&index.table,i,&keyBase)); ++index.count; }
            for(std::uint32_t i=0;i<n;++i) { assert(find(&index,&index.keys[i])==i); ++lookups; }
            std::uint32_t corrupt=0;
            while(corrupt<capacity && (slots[corrupt].index==a::kEnd || corrupt==a::kEnd)) ++corrupt;
            // One-key direct home FFFF cannot be turned into a self-cycle with its
            // reserved link value; move it to another physical slot to orphan it.
            if(corrupt==capacity) { assert(n==1 && capacity==65536); slots[0]=slots[a::kEnd]; slots[a::kEnd]={}; }
            else slots[corrupt].next=static_cast<std::uint16_t>(corrupt);
            a::Snapshot snapshot{slots.data(),capacity,index.keys,n+1,n,capacity-1,index.table.available,index.table.lastFree};
            const auto result=a::BuildRepair(snapshot,out.data(),out.size());
            assert(result.status==a::BuildStatus::Ready);
            index.table.entries=out.data(); index.table.available=result.available; index.table.lastFree=result.lastFree; ++index.count;
            for(std::uint32_t i=0;i<index.count;++i) { assert(find(&index,&index.keys[i])==i); ++lookups; }
            a::Key absent{index.keys[0].word0,0xDEADBEEFu,0xCAFEBABEu};
            assert(find(&index,&absent)==index.count); ++lookups;
            if(index.count<256 && index.count<capacity) {
                index.keys[index.count]={static_cast<std::uint32_t>(rng()),index.count,trial};
                assert(insert(&index.table,index.count,&keyBase)); ++index.count;
                for(std::uint32_t i=0;i<index.count;++i) { assert(find(&index,&index.keys[i])==i); ++lookups; }
            }
            ++cases;
        }
    }
    {
        const std::uint32_t capacity=65536;
        std::vector<a::Entry> slots(capacity),out(capacity);
        NativeIndex index;
        index.keys[0]={1,2,3}; index.keys[1]={1,4,5};
        index.table={0,slots.data(),capacity,capacity-1,capacity,0};
        auto* keys=index.keys;
        assert(insert(&index.table,0,&keys)); index.count=1;
        a::Snapshot snapshot{slots.data(),capacity,index.keys,2,1,capacity-1,capacity-1,0};
        auto result=a::BuildRepair(snapshot,out.data(),out.size());
        assert(result.status==a::BuildStatus::Ready);
        assert(insert(&index.table,1,&keys)); index.count=2;
        assert(slots[a::kEnd].index==1);
        assert(find(&index,&index.keys[1])==2); // native reports missing despite successful insert
        index.table.entries=out.data(); index.table.available=result.available; index.table.lastFree=result.lastFree;
        assert(find(&index,&index.keys[0])==0 && find(&index,&index.keys[1])==1);
        std::puts("PASS: original bytes reproduce sentinel-overflow lost lookup; staged repair preserves both entries");
    }
    std::printf("PASS: %u synthetic recovery cases; %u original-engine lookup checks; healthy original inserts and post-repair original inserts succeeded\n",cases,lookups);
}
