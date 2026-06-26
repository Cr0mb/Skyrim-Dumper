#include "pe.h"
#include "log.h"

#include <Windows.h>
#include <cstring>

namespace pe {

bool ParseImage(const proc::Attached& a, ImageInfo& out) {
    IMAGE_DOS_HEADER dos{};
    if (!proc::ReadT(a, a.base, &dos)) {
        dlog::Error("pe::ParseImage: failed to read DOS header at base");
        return false;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        dlog::Error("pe::ParseImage: bad DOS magic 0x%04X", dos.e_magic);
        return false;
    }
    IMAGE_NT_HEADERS64 nt{};
    if (!proc::ReadT(a, a.base + dos.e_lfanew, &nt)) {
        dlog::Error("pe::ParseImage: failed to read NT headers");
        return false;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE) {
        dlog::Error("pe::ParseImage: bad NT signature 0x%08X", nt.Signature);
        return false;
    }

    out.machine         = nt.FileHeader.Machine;
    out.num_sections    = nt.FileHeader.NumberOfSections;
    out.timestamp       = nt.FileHeader.TimeDateStamp;
    out.entry_rva       = nt.OptionalHeader.AddressOfEntryPoint;
    out.image_base      = nt.OptionalHeader.ImageBase;
    out.size_of_image   = nt.OptionalHeader.SizeOfImage;
    out.size_of_headers = nt.OptionalHeader.SizeOfHeaders;
    out.dll_chars       = nt.OptionalHeader.DllCharacteristics;

    // Section table follows the NT headers.
    uintptr_t sect_va = a.base + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    out.sections.reserve(out.num_sections);
    out.by_name.reserve(out.num_sections);
    for (uint16_t i = 0; i < out.num_sections; ++i) {
        IMAGE_SECTION_HEADER sh{};
        if (!proc::ReadT(a, sect_va + i * sizeof(sh), &sh)) {
            dlog::Warn("pe::ParseImage: section[%u] read failed", i);
            continue;
        }
        Section s;
        char nm[9] = {};
        memcpy(nm, sh.Name, 8);
        s.name  = nm;
        s.rva   = sh.VirtualAddress;
        s.vsize = sh.Misc.VirtualSize;
        s.chars = sh.Characteristics;
        out.by_name[s.name] = out.sections.size();
        out.sections.push_back(std::move(s));
    }
    return true;
}

bool ReadSection(const proc::Attached& a, const ImageInfo& info,
                 const std::string& name, std::vector<uint8_t>& out) {
    // Always linear-search and pick the FIRST match. Skyrim has two ".text"
    // sections (the second is the SteamStub bootstrap stub at the tail of
    // the image); by_name is order-dependent and gives us the wrong one.
    for (const auto& s : info.sections) {
        if (s.name == name) {
            return proc::ReadRange(a, a.base + s.rva, s.vsize, out);
        }
    }
    dlog::Warn("pe::ReadSection: section '%s' not found", name.c_str());
    return false;
}

const Section* SectionFromRva(const ImageInfo& info, uint32_t rva) {
    for (const auto& s : info.sections) {
        if (rva >= s.rva && rva < s.rva + s.vsize) return &s;
    }
    return nullptr;
}

} // namespace pe
