#include "data_scan.h"
#include "log.h"

#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

namespace data_scan {

bool Scan(const proc::Attached& a,
          const std::vector<rtti::ClassEntry>& classes,
          const Args& args,
          std::vector<SlotMatch>& out) {
    if (!args.data_bytes || args.data_bytes->empty()) {
        dlog::Error("data_scan: data buffer missing");
        return false;
    }
    const auto& data = *args.data_bytes;
    const uint64_t base = (uint64_t)a.base;

    // Build vtable_va -> class lookup.
    std::unordered_map<uint64_t, const rtti::ClassEntry*> vt_to_class;
    vt_to_class.reserve(classes.size());
    for (const auto& c : classes) {
        vt_to_class.emplace(base + c.vtable_rva, &c);
    }

    // Plausible user-mode heap pointer range — Windows 10/11 hands user-mode
    // VAs in [0x10000, 0x7FFFFFFEFFFF]. Module images sit at the high end of
    // that range. Heap pointers from the CRT/NT allocator generally fall in
    // the same span. We accept anything in user space.
    constexpr uint64_t LO = 0x0000000000010000ull;
    constexpr uint64_t HI = 0x00007FFFFFFEFFFFull;

    // Phase 1: collect unique heap pointers from .data.
    std::unordered_set<uint64_t> uniq;
    uniq.reserve(1 << 16);
    const size_t n = data.size() / 8;
    const uint64_t* p = reinterpret_cast<const uint64_t*>(data.data());
    for (size_t i = 0; i < n; ++i) {
        uint64_t v = p[i];
        if (v < LO || v > HI) continue;
        uniq.insert(v);
    }
    dlog::Info("data_scan: %zu distinct heap pointers in .data", uniq.size());

    // Phase 2: read vtable qword for each distinct pointer (one RPM each).
    // Map deref'd vtable VA -> originating object pointer for use below.
    std::unordered_map<uint64_t, uint64_t> ptr_to_vtable;
    ptr_to_vtable.reserve(uniq.size());
    size_t reads_ok = 0, reads_fail = 0;
    for (uint64_t obj_va : uniq) {
        uint64_t vt = 0;
        if (proc::ReadT(a, (uintptr_t)obj_va, &vt)) {
            ptr_to_vtable.emplace(obj_va, vt);
            ++reads_ok;
        } else {
            ++reads_fail;
        }
    }
    dlog::Info("data_scan: vtable reads ok=%zu fail=%zu", reads_ok, reads_fail);

    // Phase 3: walk .data again, emit matches for every slot whose deref'd
    // vtable corresponds to a known class.
    for (size_t i = 0; i < n; ++i) {
        uint64_t v = p[i];
        if (v < LO || v > HI) continue;
        auto pv = ptr_to_vtable.find(v);
        if (pv == ptr_to_vtable.end()) continue;
        auto vc = vt_to_class.find(pv->second);
        if (vc == vt_to_class.end()) continue;
        SlotMatch m;
        m.slot_rva   = args.data_rva + (uint32_t)(i * 8);
        m.class_name = vc->second->name;
        m.vtable_rva = vc->second->vtable_rva;
        m.obj_va     = (uintptr_t)v;
        out.push_back(std::move(m));
    }

    // Sort: by class name, then slot rva.
    std::sort(out.begin(), out.end(), [](const SlotMatch& a, const SlotMatch& b) {
        if (a.class_name != b.class_name) return a.class_name < b.class_name;
        return a.slot_rva < b.slot_rva;
    });

    dlog::Info("data_scan: %zu .data slots resolved to a known class",
               out.size());
    return true;
}

} // namespace data_scan
