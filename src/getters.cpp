#include "getters.h"
#include "log.h"

#include <cstring>
#include <unordered_map>

namespace getters {

namespace {

inline bool RvaIn(uint32_t r, uint32_t base, uint32_t sz) {
    return r >= base && r < base + sz;
}

} // anon

bool Scan(const proc::Attached& a,
          const pe::ImageInfo& info,
          const std::vector<rtti::ClassEntry>& classes,
          const Args& args,
          std::vector<Resolved>& out) {
    if (!args.text_bytes || args.text_bytes->empty()) {
        dlog::Error("getters::Scan: text buffer missing");
        return false;
    }
    const auto& text = *args.text_bytes;
    const uint64_t base = (uint64_t)a.base;

    // Build vtable_va -> class for fast lookup.
    std::unordered_map<uint64_t, const rtti::ClassEntry*> vt_to_class;
    vt_to_class.reserve(classes.size());
    for (const auto& c : classes) {
        vt_to_class.emplace(base + c.vtable_rva, &c);
    }

    // Deduplicate by slot RVA — pattern A and B occasionally coexist for the
    // same singleton; keep the first one we see, prefer pattern A.
    std::unordered_map<uint32_t, Resolved> by_slot;

    size_t pat_a_hits = 0, pat_b_hits = 0;

    // Pattern A: 48 8B 05 disp32 C3   (8 bytes total)
    if (text.size() >= 8) {
        const size_t end = text.size() - 8;
        for (size_t i = 0; i <= end; ++i) {
            if (text[i]     != 0x48) continue;
            if (text[i + 1] != 0x8B) continue;
            if (text[i + 2] != 0x05) continue;
            if (text[i + 7] != 0xC3) continue;
            int32_t d = 0;
            memcpy(&d, &text[i + 3], 4);
            uint64_t next_ip  = (uint64_t)args.text_rva + (uint64_t)i + 7;
            uint64_t slot_va  = next_ip + (int64_t)d;
            if (slot_va < (uint64_t)args.data_rva ||
                slot_va >= (uint64_t)args.data_rva + args.data_size) continue;
            uint32_t slot_rva = (uint32_t)slot_va;
            ++pat_a_hits;

            Resolved r;
            r.getter_rva = args.text_rva + (uint32_t)i;
            r.slot_rva   = slot_rva;
            r.pattern    = 'A';

            // Live verification: slot holds T*, T* has vtable at +0.
            uintptr_t storage_va = (uintptr_t)base + slot_rva;
            uintptr_t obj_va = 0;
            if (proc::ReadT(a, storage_va, &obj_va) && obj_va) {
                uintptr_t vt_va = 0;
                if (proc::ReadT(a, obj_va, &vt_va)) {
                    auto it = vt_to_class.find((uint64_t)vt_va);
                    if (it != vt_to_class.end()) {
                        r.class_name = it->second->name;
                        r.vtable_rva = it->second->vtable_rva;
                        r.verified   = true;
                    }
                }
            }

            auto ins = by_slot.emplace(slot_rva, r);
            if (!ins.second && !ins.first->second.verified && r.verified) {
                ins.first->second = r;
            }
        }
    }
    dlog::Info("getters: pattern A (mov+ret) hits=%zu", pat_a_hits);

    // Pattern B: 48 8B 05 disp32 48 8B 00 C3   (10 bytes total)
    if (text.size() >= 10) {
        const size_t end = text.size() - 10;
        for (size_t i = 0; i <= end; ++i) {
            if (text[i]     != 0x48) continue;
            if (text[i + 1] != 0x8B) continue;
            if (text[i + 2] != 0x05) continue;
            if (text[i + 7] != 0x48) continue;
            if (text[i + 8] != 0x8B) continue;
            if (text[i + 9] != 0x00) continue;
            if (i + 10 >= text.size() || text[i + 10] != 0xC3) continue;
            int32_t d = 0;
            memcpy(&d, &text[i + 3], 4);
            uint64_t next_ip = (uint64_t)args.text_rva + (uint64_t)i + 7;
            uint64_t slot_va = next_ip + (int64_t)d;
            if (slot_va < (uint64_t)args.data_rva ||
                slot_va >= (uint64_t)args.data_rva + args.data_size) continue;
            uint32_t slot_rva = (uint32_t)slot_va;
            ++pat_b_hits;

            Resolved r;
            r.getter_rva = args.text_rva + (uint32_t)i;
            r.slot_rva   = slot_rva;
            r.pattern    = 'B';

            // Pattern B reads through one extra level: slot_va contains
            // address-of-slot, which itself holds T*.
            uintptr_t storage_va = (uintptr_t)base + slot_rva;
            uintptr_t indirect   = 0;
            if (proc::ReadT(a, storage_va, &indirect) && indirect) {
                uintptr_t obj_va = 0;
                if (proc::ReadT(a, indirect, &obj_va) && obj_va) {
                    uintptr_t vt_va = 0;
                    if (proc::ReadT(a, obj_va, &vt_va)) {
                        auto it = vt_to_class.find((uint64_t)vt_va);
                        if (it != vt_to_class.end()) {
                            r.class_name = it->second->name;
                            r.vtable_rva = it->second->vtable_rva;
                            r.verified   = true;
                        }
                    }
                }
            }

            auto ins = by_slot.emplace(slot_rva, r);
            if (!ins.second && !ins.first->second.verified && r.verified) {
                ins.first->second = r;
            }
        }
    }
    dlog::Info("getters: pattern B (mov+deref+ret) hits=%zu", pat_b_hits);

    out.reserve(by_slot.size());
    for (auto& kv : by_slot) out.push_back(kv.second);

    size_t verified = 0;
    for (auto& r : out) if (r.verified) ++verified;
    dlog::Info("getters: %zu distinct slots, %zu verified to a class",
               out.size(), verified);
    return true;
}

} // namespace getters
