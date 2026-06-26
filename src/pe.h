// =============================================================================
//  pe.h — minimal PE structural extraction over a live module image.
//
//  Parses the in-memory PE header (already laid out by the loader, so
//  section.VirtualAddress is what we want — no on-disk file-offset math).
//  Output is a SectionMap (name -> rva,size) so the rest of the dumper
//  can talk in "give me the .text bytes" without re-walking headers.
// =============================================================================
#pragma once

#include "process.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace pe {

struct Section {
    std::string name;
    uint32_t    rva   = 0;
    uint32_t    vsize = 0;
    uint32_t    chars = 0;   // IMAGE_SCN_*
};

struct ImageInfo {
    uint16_t   machine          = 0;
    uint16_t   num_sections     = 0;
    uint32_t   timestamp        = 0;
    uint32_t   entry_rva        = 0;
    uint64_t   image_base       = 0;   // preferred (PE header) base — not necessarily current
    uint32_t   size_of_image    = 0;
    uint32_t   size_of_headers  = 0;
    uint16_t   dll_chars        = 0;
    std::vector<Section> sections;
    std::unordered_map<std::string, size_t> by_name;  // name -> index into sections
};

// Read enough of the headers out of the live process to populate ImageInfo.
bool ParseImage(const proc::Attached& a, ImageInfo& out);

// Pull an entire section's bytes (size = VirtualSize) into a buffer.
bool ReadSection(const proc::Attached& a, const ImageInfo& info,
                 const std::string& name, std::vector<uint8_t>& out);

// Convert a raw RVA into a buffer-relative offset given the section that
// owns it. Returns false if rva isn't in this section.
inline bool RvaToOffset(const Section& s, uint32_t rva, size_t* off) {
    if (rva < s.rva || rva >= s.rva + s.vsize) return false;
    *off = rva - s.rva;
    return true;
}

// Find which section owns an RVA (linear scan — sections are few).
const Section* SectionFromRva(const ImageInfo& info, uint32_t rva);

} // namespace pe
