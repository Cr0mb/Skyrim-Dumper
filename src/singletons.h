// =============================================================================
//  singletons.h — singleton storage discovery.
//
//  For Creation Engine, every major class follows the pattern:
//      static T* GetSingleton() { return *reinterpret_cast<T**>(g_singleton); }
//  with the singleton being assigned ONCE inside the constructor:
//      <ctor>: ... mov [rip+disp_to_g_singleton], rcx ; ret
//
//  Given a vtable RVA from rtti::Walk, we:
//    1. Find every absolute pointer to this vtable in .text — those are
//       call sites that build instances of the class. Among them is at least
//       one constructor that writes the singleton.
//    2. For each such reference, scan ~256 bytes forward for the byte
//       sequence `48 89 0D ?? ?? ?? ??` (mov [rip+disp32], rcx) or
//       `48 89 05 ?? ?? ?? ??` (mov [rip+disp32], rax) — both patterns
//       occur depending on which register holds `this`. The disp32 plus
//       the instruction's end-of-instruction RVA gives us the storage RVA.
//    3. Emit the first storage RVA whose target lies in .data; ignore ones
//       in .rdata (those are vtable assignments, not singletons).
//
//  Limitations: false positives possible (any function that happens to write
//  back to a .data global within 256 bytes of using the class's vtable). For
//  the 10ish classes we look for, the noise is acceptable; cross-check the
//  output by running the trainer and dereferencing the slot.
// =============================================================================
#pragma once

#include "pe.h"
#include "rtti.h"

#include <cstdint>
#include <string>
#include <vector>

namespace singletons {

struct Resolved {
    std::string class_name;        // e.g. "PlayerCharacter"
    uint32_t    vtable_rva   = 0;
    uint32_t    singleton_rva = 0; // RVA of the g_singleton slot in .data
    uint32_t    ctor_rva     = 0;  // RVA of the constructor that wrote it
};

struct Args {
    const std::vector<uint8_t>* text_bytes  = nullptr;
    const std::vector<uint8_t>* rdata_bytes = nullptr;
    uint32_t text_rva  = 0;
    uint32_t rdata_rva = 0;
    uint32_t data_rva  = 0;
    uint32_t data_size = 0;
};

// targets: list of class names to resolve (matched against rtti::ClassEntry.name).
bool Find(const proc::Attached& a,
          const pe::ImageInfo& info,
          const std::vector<rtti::ClassEntry>& classes,
          const Args& args,
          const std::vector<std::string>& targets,
          std::vector<Resolved>& out);

} // namespace singletons
