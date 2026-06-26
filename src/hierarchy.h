// =============================================================================
//  hierarchy.h — walk the MSVC RTTI ClassHierarchyDescriptor chain to
//  recover each class's full base-class list.
//
//  COL contains a CHD RVA. CHD has { signature, attributes, num_bases,
//  pBaseClassArray (RVA) }. pBaseClassArray points at an array of
//  BaseClassDescriptor RVAs. Each BCD has { pTypeDescriptor (RVA),
//  num_contained_bases, ... }.
//
//  So for each class, the chain TypeDescriptor RVAs in pBaseClassArray
//  are exactly its base classes in MRO order (most-derived first).
// =============================================================================
#pragma once

#include "pe.h"
#include "rtti.h"
#include <cstdint>
#include <string>
#include <vector>

namespace hierarchy {

struct Row {
    std::string class_name;
    uint32_t    col_rva    = 0;
    uint32_t    vtable_rva = 0;
    std::vector<std::string> bases;     // ordered by inheritance walk
};

struct Args {
    const std::vector<uint8_t>* rdata_bytes = nullptr;
    const std::vector<uint8_t>* data_bytes  = nullptr;
    uint32_t rdata_rva = 0;
    uint32_t data_rva  = 0;
};

bool Build(const proc::Attached& a,
           const std::vector<rtti::ClassEntry>& classes,
           const Args& args,
           std::vector<Row>& out);

} // namespace hierarchy
