// =============================================================================
//  vtable_dump.h — emit one CSV row per vfunc per vtable.
//
//  We already know each vtable's RVA and vfunc count from the RTTI walk.
//  This pass re-reads the vfunc pointer array out of the .rdata buffer (no
//  extra RPM needed) and writes per-row entries the trainer can index by
//  (class_name, vfunc_index).
// =============================================================================
#pragma once

#include "pe.h"
#include "rtti.h"
#include <cstdint>
#include <string>
#include <vector>

namespace vtable_dump {

struct Row {
    std::string class_name;
    uint32_t    vtable_rva = 0;
    uint32_t    vfunc_idx  = 0;
    uint32_t    vfunc_rva  = 0;
};

struct Args {
    const std::vector<uint8_t>* rdata_bytes = nullptr;
    uint32_t rdata_rva = 0;
    uint32_t text_rva  = 0;
};

bool Dump(const proc::Attached& a,
          const std::vector<rtti::ClassEntry>& classes,
          const Args& args,
          std::vector<Row>& out);

} // namespace vtable_dump
