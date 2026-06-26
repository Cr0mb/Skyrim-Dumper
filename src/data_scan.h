// =============================================================================
//  data_scan.h — exhaustive .data slot → class resolver.
//
//  Brute-forces the problem: every 8-byte-aligned slot in `.data` is read
//  from the buffer we already pulled. For each slot whose value looks like
//  a heap pointer (above module base, below user-space ceiling), we read
//  the pointed-to qword (the would-be vtable) via a single RPM call, then
//  match against the RTTI vtable catalog.
//
//  We dedupe deref calls (many slots point to the same global object), so
//  total RPM count is roughly the number of distinct heap pointers in
//  `.data` — typically a few thousand on a running Skyrim, ~1 second.
//
//  Output: one entry per (slot_rva, class) match. Classes can have many
//  slots pointing at them (e.g. the player pointer is mirrored in dozens
//  of subsystem fields); we emit all of them.
// =============================================================================
#pragma once

#include "pe.h"
#include "rtti.h"
#include <cstdint>
#include <string>
#include <vector>

namespace data_scan {

struct SlotMatch {
    uint32_t    slot_rva   = 0;   // RVA of the .data slot that holds the pointer
    std::string class_name;       // class whose vtable the deref'd object has
    uint32_t    vtable_rva = 0;
    uintptr_t   obj_va     = 0;   // live heap address pointed to
};

struct Args {
    const std::vector<uint8_t>* data_bytes = nullptr;
    uint32_t data_rva = 0;
};

bool Scan(const proc::Attached& a,
          const std::vector<rtti::ClassEntry>& classes,
          const Args& args,
          std::vector<SlotMatch>& out);

} // namespace data_scan
