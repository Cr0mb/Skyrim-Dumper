// =============================================================================
//  rtti.h — MSVC x64 RTTI walker.
//
//  On x64 MSVC binaries, RTTI gives us a near-complete inventory of every
//  polymorphic class in the binary. Three structures collaborate:
//
//   TypeDescriptor  (in .data, occasionally .rdata)
//     +0x00  vtable ptr to type_info  -- all type_descs share one vtable
//     +0x08  spare (always 0)
//     +0x10  null-terminated MSVC-mangled name like ".?AVTESForm@@"
//
//   CompleteObjectLocator  (in .rdata)
//     +0x00  signature  (1 == x64 image)
//     +0x04  offset of vtable within object
//     +0x08  ctor displacement offset
//     +0x0C  TypeDescriptor RVA              <-- KEY: 4-byte RVA, not 8-byte ptr
//     +0x10  ClassHierarchyDescriptor RVA
//     +0x14  COL self-RVA                    <-- used to recover image base
//
//   Vtable  (in .rdata)
//     vtable[-1]   ABSOLUTE pointer to its COL  (8 bytes)
//     vtable[0..N] virtual function pointers (each into .text)
//
//  Walk strategy:
//     1. Scan .rdata bytes for the literal ".?AV" / ".?AU" — these begin every
//        MSVC mangled class/struct name. Each hit is the +0x10 NAME field of
//        a TypeDescriptor; back up 0x10 to find the TypeDescriptor's base RVA.
//     2. Build a set of TypeDescriptor RVAs.
//     3. Scan .rdata for any 4-byte word equal to a TypeDescriptor RVA — each
//        hit is the COL's +0xC field. Subtract 0xC to get COL's RVA. Verify
//        COL's self-RVA field matches.
//     4. For each COL, scan .rdata for any 8-byte word equal to (image_base +
//        COL_RVA) — that's vtable[-1]. Then vtable starts 8 bytes later.
//     5. Count vfuncs by walking forward until a pointer no longer points
//        into .text.
//
//  Output: a list of (class_name, vtable_rva, n_virtuals, col_rva) entries.
//  One class can have multiple vtables (multi-inheritance bases) — we emit
//  every (class, vtable) pair we find, deduped by tuple.
// =============================================================================
#pragma once

#include "pe.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace rtti {

struct ClassEntry {
    std::string name;              // demangled-ish: stripped ".?AV" prefix + "@@" suffix
    std::string raw_name;          // ".?AVTESForm@@"
    uint32_t    type_desc_rva = 0;
    uint32_t    col_rva       = 0;
    uint32_t    vtable_rva    = 0;
    uint32_t    n_virtuals    = 0;
};

struct WalkArgs {
    // Buffers caller has already pulled (avoid re-RPMing huge ranges).
    //   text_bytes  — to validate vfunc pointers point into .text
    //   rdata_bytes — where COL records and vtables live
    //   data_bytes  — where TypeDescriptors live on this build
    //                 (MSVC x64; type_info vtable ptr at TD+0 means TD must
    //                 sit in a writable section to be initialized at load)
    const std::vector<uint8_t>* rdata_bytes = nullptr;
    const std::vector<uint8_t>* text_bytes  = nullptr;
    const std::vector<uint8_t>* data_bytes  = nullptr;
    uint32_t rdata_rva = 0;
    uint32_t text_rva  = 0;
    uint32_t data_rva  = 0;
};

bool Walk(const proc::Attached& a, const pe::ImageInfo& info,
          const WalkArgs& args, std::vector<ClassEntry>& out);

// Lookup helper built from a Walk() result.
class Index {
public:
    void Build(const std::vector<ClassEntry>& entries);
    const ClassEntry* FindByName(const std::string& demangled) const;
    const std::vector<const ClassEntry*>* FindAllByName(const std::string& demangled) const;
private:
    std::unordered_map<std::string, std::vector<const ClassEntry*>> m_by_name;
};

} // namespace rtti
