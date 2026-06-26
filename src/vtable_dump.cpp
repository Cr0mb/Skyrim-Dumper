#include "vtable_dump.h"
#include "log.h"

namespace vtable_dump {

bool Dump(const proc::Attached& a,
          const std::vector<rtti::ClassEntry>& classes,
          const Args& args,
          std::vector<Row>& out) {
    if (!args.rdata_bytes || args.rdata_bytes->empty()) {
        dlog::Error("vtable_dump: rdata buffer missing");
        return false;
    }
    const auto& rdata = *args.rdata_bytes;
    const uint64_t base = (uint64_t)a.base;
    size_t emitted = 0;
    for (const auto& c : classes) {
        if (c.n_virtuals == 0) continue;
        // Compute offset of the first vfunc slot within the rdata buffer.
        if (c.vtable_rva < args.rdata_rva) continue;
        size_t off = (size_t)(c.vtable_rva - args.rdata_rva);
        for (uint32_t i = 0; i < c.n_virtuals; ++i) {
            size_t slot_off = off + (size_t)i * 8;
            if (slot_off + 8 > rdata.size()) break;
            uint64_t ptr = 0;
            std::memcpy(&ptr, &rdata[slot_off], 8);
            if (ptr < base) continue;
            uint64_t rva = ptr - base;
            if (rva > 0xFFFFFFFFu) continue;
            Row r;
            r.class_name = c.name;
            r.vtable_rva = c.vtable_rva;
            r.vfunc_idx  = i;
            r.vfunc_rva  = (uint32_t)rva;
            out.push_back(std::move(r));
            ++emitted;
        }
    }
    dlog::Info("vtable_dump: %zu vfunc rows across %zu classes",
               emitted, classes.size());
    return true;
}

} // namespace vtable_dump
