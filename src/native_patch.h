#pragma once

// Native key-access corrections for Daytripper4's extended archive storage.
//
// Daytripper4 keeps archive keys 0..254 inline and moves 255 and above into a
// std::vector<ResourceID> reached through fixed slot 255. The engine's insertion
// and collision-loop code still computes key addresses as
// parent + 0x1030 + index * 12, which is wrong for extended indices.
//
// Each correction replaces one instruction window with a call to a stub that
// preserves every register except the one the window produced, asks the plugin
// for the real key address, and reproduces the instruction it displaced.

#include <array>
#include <cstdint>
#include <initializer_list>
#include <vector>

namespace freezefix {
namespace native {

// archive_lookup + 0xBB: lea rdx,[r9+r9*2]; lea r8,[r11+rdx*4]
inline constexpr std::uintptr_t kLookupLoopRva = 0x1B78BAB;
inline constexpr std::array<std::uint8_t, 8> kLookupLoopOriginal{
    0x4B, 0x8D, 0x14, 0x49, 0x4D, 0x8D, 0x04, 0x93};

// archive_insert + 0x25: mov ebx,[rax+r9*4]; mov r14,r8
inline constexpr std::uintptr_t kInsertIncomingRva = 0x1B77315;
inline constexpr std::array<std::uint8_t, 7> kInsertIncomingOriginal{
    0x42, 0x8B, 0x1C, 0x88, 0x4D, 0x8B, 0xF0};

// archive_insert + 0xA2: mov r9d,[rax+rcx*4]; and r9d,edi
inline constexpr std::uintptr_t kInsertDisplacedRva = 0x1B77392;
inline constexpr std::array<std::uint8_t, 7> kInsertDisplacedOriginal{
    0x44, 0x8B, 0x0C, 0x88, 0x44, 0x23, 0xCF};

namespace detail {

inline void Emit(std::vector<std::uint8_t>& code, std::initializer_list<std::uint8_t> bytes) {
    code.insert(code.end(), bytes.begin(), bytes.end());
}

inline void EmitHelper(std::vector<std::uint8_t>& code, std::uintptr_t helper) {
    Emit(code, {0x48, 0xB8});  // movabs rax, helper
    for (unsigned i = 0; i < 8; ++i)
        code.push_back(static_cast<std::uint8_t>(helper >> (8 * i)));
    Emit(code, {0xFF, 0xD0});  // call rax
}

// Every stub saves the volatile registers it may clobber, reserves the 32-byte
// shadow space, and restores them before returning to the patched window.
inline void EmitPrologue(std::vector<std::uint8_t>& code) {
    Emit(code, {0x50, 0x51, 0x52});                          // push rax, rcx, rdx
    Emit(code, {0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53});  // push r8..r11
    Emit(code, {0x48, 0x83, 0xEC, 0x20});                    // sub rsp, 0x20
}

inline void EmitEpilogue(std::vector<std::uint8_t>& code) {
    Emit(code, {0x48, 0x83, 0xC4, 0x20});                    // add rsp, 0x20
    Emit(code, {0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58});  // pop r11..r8
    Emit(code, {0x5A, 0x59});                                // pop rdx, rcx
}

}  // namespace detail

// r9 = member index, r11 = parent. Produces r8 = keyAddress - 0x1030 so the
// following mov 0x1030(%r8) reads the real key.
inline std::vector<std::uint8_t> BuildLookupStub(std::uintptr_t helper) {
    std::vector<std::uint8_t> code;
    detail::EmitPrologue(code);
    detail::Emit(code, {0x49, 0x8D, 0x8B, 0x30, 0x10, 0x00, 0x00});  // lea rcx,[r11+0x1030]
    detail::Emit(code, {0x44, 0x89, 0xCA});                          // mov edx, r9d
    detail::EmitHelper(code, helper);
    detail::EmitEpilogue(code);
    detail::Emit(code, {0x4C, 0x8D, 0x80, 0xD0, 0xEF, 0xFF, 0xFF});  // lea r8,[rax-0x1030]
    detail::Emit(code, {0x58, 0xC3});                                // pop rax; ret
    return code;
}

// rax = key array, r11 = incoming index, r8 = key-array argument.
// Produces ebx = key.word0 and reproduces mov r14,r8.
inline std::vector<std::uint8_t> BuildIncomingStub(std::uintptr_t helper) {
    std::vector<std::uint8_t> code;
    detail::EmitPrologue(code);
    detail::Emit(code, {0x48, 0x89, 0xC1});  // mov rcx, rax
    detail::Emit(code, {0x44, 0x89, 0xDA});  // mov edx, r11d
    detail::EmitHelper(code, helper);
    detail::Emit(code, {0x8B, 0x18});        // mov ebx, [rax]
    detail::EmitEpilogue(code);
    detail::Emit(code, {0x4D, 0x89, 0xC6});  // mov r14, r8
    detail::Emit(code, {0x58, 0xC3});        // pop rax; ret
    return code;
}

// rax = key array, rcx = index*3, esi = entry. Produces r9d = key.word0 & mask
// and reproduces and r9d,edi.
inline std::vector<std::uint8_t> BuildDisplacedStub(std::uintptr_t helper) {
    std::vector<std::uint8_t> code;
    detail::EmitPrologue(code);
    detail::Emit(code, {0x48, 0x89, 0xC1});  // mov rcx, rax
    detail::Emit(code, {0x89, 0xF2});        // mov edx, esi
    detail::Emit(code, {0xC1, 0xEA, 0x10});  // shr edx, 16
    detail::EmitHelper(code, helper);
    detail::EmitEpilogue(code);
    detail::Emit(code, {0x44, 0x8B, 0x08});  // mov r9d, [rax]
    // REX.R (0x44) extends the destination; 0x41 would be REX.B and encode
    // "and ecx, r15d", leaving r9d unmasked.
    detail::Emit(code, {0x44, 0x23, 0xCF});  // and r9d, edi
    detail::Emit(code, {0x58, 0xC3});        // pop rax; ret
    return code;
}

}  // namespace native
}  // namespace freezefix
