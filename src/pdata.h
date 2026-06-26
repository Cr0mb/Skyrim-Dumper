// =============================================================================
//  pdata.h — x64 exception/unwind data is also the function table.
//
//  Every x64 PE has an .pdata section (or pdata.exception data directory)
//  containing an array of RUNTIME_FUNCTION { BeginAddress, EndAddress,
//  UnwindInfoAddress } — one entry per leaf-or-non-leaf function. Skyrim
//  has no exports, so .pdata IS our function table. Walking it gives us
//  function boundaries for free, no disassembly required.
// =============================================================================
#pragma once

#include "pe.h"
#include <cstdint>
#include <vector>

namespace pdata {

struct Function {
    uint32_t begin_rva    = 0;
    uint32_t end_rva      = 0;
    uint32_t unwind_rva   = 0;
    uint32_t size() const { return end_rva - begin_rva; }
};

bool Walk(const proc::Attached& a, const pe::ImageInfo& info,
          std::vector<Function>& out);

// Quick stats — printed to the consolidated log.
struct Stats {
    size_t   count          = 0;
    uint32_t total_bytes    = 0;
    uint32_t min_size       = UINT32_MAX;
    uint32_t max_size       = 0;
    uint32_t mean_size      = 0;
};
Stats Summarize(const std::vector<Function>& fns);

} // namespace pdata
