// =============================================================================
//  getters.h — singleton discovery via the accessor pattern.
//
//  Every Creation Engine singleton uses one of two tiny getter functions:
//
//      static T* GetSingleton() { return g_t_ptr; }                // pattern A
//      static T* GetSingleton() { return *g_t_ptr_addr; }          // pattern B
//
//  Compiled forms:
//
//    Pattern A (8 bytes): `mov rax, [rip+disp]; ret`
//        48 8B 05 disp32   ; rax = [rip+disp]  -> the singleton T*
//        C3                ; ret
//
//    Pattern B (10 bytes): `mov rax, [rip+disp]; mov rax, [rax]; ret`
//        48 8B 05 disp32   ; rax = address of slot
//        48 8B 00          ; rax = [rax]
//        C3
//
//  Both patterns are uniquely identifying — vanishingly few non-getter
//  functions are exactly this small. The 4 missing singletons (Main, TES,
//  Sky, Console) all use one of these accessors regardless of how their
//  constructors are written, so this finds them where the ctor-anchor
//  approach failed.
//
//  Match storage→class by reading the slot from the live process,
//  dereferencing once or twice (per pattern), and looking up the resulting
//  vtable in the RTTI catalog.
// =============================================================================
#pragma once

#include "pe.h"
#include "rtti.h"
#include <cstdint>
#include <string>
#include <vector>

namespace getters {

struct Resolved {
    std::string class_name;          // empty if no RTTI match
    uint32_t    getter_rva   = 0;    // RVA of the `48 8B 05` byte
    uint32_t    slot_rva     = 0;    // RVA the getter reads (singleton storage)
    uint32_t    vtable_rva   = 0;    // empty (0) if unmatched
    uint8_t     pattern      = 0;    // 'A' or 'B'
    bool        verified     = false;
};

struct Args {
    const std::vector<uint8_t>* text_bytes = nullptr;
    uint32_t text_rva  = 0;
    uint32_t data_rva  = 0;
    uint32_t data_size = 0;
};

// Scan .text for both accessor patterns. For each hit, attempt live
// verification against the running process and resolve a class name.
bool Scan(const proc::Attached& a,
          const pe::ImageInfo& info,
          const std::vector<rtti::ClassEntry>& classes,
          const Args& args,
          std::vector<Resolved>& out);

} // namespace getters
