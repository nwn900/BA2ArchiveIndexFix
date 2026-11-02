// Optional Linux x86-64 differential test; no game machine code is bundled.
// The Python driver verifies user-supplied bytes before running this process.
#include "archive_index.h"

#ifdef NDEBUG
#error Native validation requires assertions to remain enabled.
#endif
#include <sys/mman.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cassert>
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
int main(int argc, char** argv) {
    if (argc != 3) {
        std::fputs("Use tests/run_native_validation.py to verify and provide the two routine fixtures.\n", stderr);
        return 2;
    }
    Code insertCode(argv[1],0x16a);
    Code findCode(argv[2],0xfe);
    auto insert=reinterpret_cast<InsertFn>(insertCode.memory);
    auto find=reinterpret_cast<FindFn>(findCode.memory);
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
