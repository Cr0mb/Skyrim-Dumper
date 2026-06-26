#include "singletons.h"
#include "log.h"

#include <cstring>
#include <unordered_set>

namespace singletons {

namespace {

bool RvaIn(uint32_t rva, uint32_t base_rva, uint32_t size) {
    return rva >= base_rva && rva < base_rva + size;
}

// Find the unambiguous constructor-prologue pattern:
//      48 8D 05 disp32   lea rax, [rip+vtable]   (7 bytes)
//      48 89 01          mov [rcx], rax          (3 bytes)
//
// The total 10-byte sequence appears nowhere except at a class constructor's
// vtable-install site — vtable comparisons use `cmp`/`mov` to load and
// compare, not the `mov [rcx], rax` store pattern.
//
// Returns offsets (in text buffer) of the FIRST byte of the LEA. Caller
// scans forward from lea_off + 10 for the singleton-store mov.
void FindCtorVtableInstalls(const std::vector<uint8_t>& text, uint32_t text_rva,
                            uint64_t target_rva,
                            std::vector<size_t>& lea_offsets_out) {
    if (text.size() < 10) return;
    const size_t end = text.size() - 10;
    for (size_t i = 0; i <= end; ++i) {
        if (text[i] != 0x48 || text[i + 1] != 0x8D || text[i + 2] != 0x05) continue;
        // Optional: also accept `mov [rcx], rax` after `mov rcx, rax` swap.
        // The common case is `lea rax, [vtable]; mov [rcx], rax`.
        if (text[i + 7]  != 0x48 ||
            text[i + 8]  != 0x89 ||
            text[i + 9]  != 0x01) continue;
        int32_t d = 0;
        memcpy(&d, &text[i + 3], 4);
        uint64_t next_ip = (uint64_t)text_rva + (uint64_t)i + 7;
        uint64_t eff     = next_ip + (int64_t)d;
        if (eff == target_rva) lea_offsets_out.push_back(i);
    }
}

// Scan up to scan_len bytes from `start` looking for a RIP-relative store:
//   48 89 0D imm32   mov [rip+imm32], rcx
//   48 89 05 imm32   mov [rip+imm32], rax
//   48 89 1D imm32   mov [rip+imm32], rbx
//   4C 89 05 imm32   mov [rip+imm32], r8
//   4C 89 0D imm32   mov [rip+imm32], r9
// All match (mod=00, rm=101). Returns the disp32 and the offset of the byte
// AFTER the instruction so the caller computes target_rva = text_rva +
// after_off + (int32)disp32.
struct MovRipMatch {
    size_t  after_off;
    int32_t disp32;
};
bool ScanForwardForRipStore(const std::vector<uint8_t>& text,
                            size_t start, size_t scan_len,
                            MovRipMatch& out) {
    if (start >= text.size()) return false;
    size_t end = start + scan_len;
    if (end > text.size()) end = text.size();
    for (size_t i = start; i + 7 <= end; ++i) {
        uint8_t b0 = text[i], b1 = text[i + 1], b2 = text[i + 2];
        bool rex48 = (b0 == 0x48);
        bool rex4c = (b0 == 0x4C);
        if (!(rex48 || rex4c)) continue;
        if (b1 != 0x89) continue;
        if ((b2 & 0xC7) != 0x05) continue;
        int32_t d = 0;
        memcpy(&d, &text[i + 3], 4);
        out.after_off = i + 7;
        out.disp32    = d;
        return true;
    }
    return false;
}

} // anon

bool Find(const proc::Attached& a,
          const pe::ImageInfo& info,
          const std::vector<rtti::ClassEntry>& classes,
          const Args& args,
          const std::vector<std::string>& targets,
          std::vector<Resolved>& out) {
    if (!args.text_bytes || args.text_bytes->empty()) {
        dlog::Error("singletons::Find: text buffer missing");
        return false;
    }
    const auto& text = *args.text_bytes;
    const uint64_t image_base_runtime = (uint64_t)a.base;

    rtti::Index idx; idx.Build(classes);
    std::unordered_set<std::string> seen;

    for (const auto& target : targets) {
        const auto* vec = idx.FindAllByName(target);
        if (!vec || vec->empty()) {
            dlog::Warn("singletons: class '%s' not present in RTTI dump",
                       target.c_str());
            continue;
        }

        // Collect the set of valid vtable VAs for this class — multi-
        // inheritance means more than one vtable can be the legitimate
        // primary for the object stored at the singleton slot.
        std::unordered_set<uint64_t> valid_vtable_vas;
        for (const auto* e : *vec) {
            valid_vtable_vas.insert(image_base_runtime + e->vtable_rva);
        }

        // Algorithm: for every LEA-to-vtable hit, scan forward up to 4 KiB
        // and collect EVERY RIP-relative store-to-.data. Then verify each
        // candidate by reading the live process — the true singleton slot
        // is one whose pointer leads to an object with one of OUR vtables.
        // Stop at the first that verifies.
        bool found_one = false;
        size_t total_lea_hits = 0, total_candidates = 0;
        // Diagnostic: collect ALL distinct candidate storage RVAs so we can
        // report what's actually there for classes that don't verify.
        struct Cand { uint32_t store_rva; uintptr_t obj_va; uintptr_t vt_va; };
        std::vector<Cand> diag_candidates;
        std::unordered_set<uint32_t> diag_seen_rvas;

        for (const auto* entry : *vec) {
            if (found_one) break;
            std::vector<size_t> lea_refs;
            FindCtorVtableInstalls(text, args.text_rva, entry->vtable_rva, lea_refs);
            total_lea_hits += lea_refs.size();

            for (size_t lea_off : lea_refs) {
                if (found_one) break;
                // Skip the LEA + `mov [rcx], rax` (10 bytes) and start
                // scanning from there.
                size_t scan_pos = lea_off + 10;
                const size_t scan_end = (scan_pos + 4096 > text.size())
                                        ? text.size() : (scan_pos + 4096);

                // Iterate every store in the scan window.
                while (scan_pos + 7 <= scan_end) {
                    MovRipMatch m{};
                    if (!ScanForwardForRipStore(text, scan_pos, scan_end - scan_pos, m)) break;
                    scan_pos = m.after_off;
                    ++total_candidates;

                    uint64_t target_rva = (uint64_t)args.text_rva
                                          + (uint64_t)m.after_off
                                          + (int64_t)m.disp32;
                    if (target_rva > 0xFFFFFFFFu) continue;
                    uint32_t store_rva = (uint32_t)target_rva;
                    if (!RvaIn(store_rva, args.data_rva, args.data_size)) continue;

                    // Verify against live process. Two singleton storage
                    // patterns are possible:
                    //   (a) pointer-to-object: slot holds a heap pointer
                    //       *slot -> object whose first qword == vtable
                    //   (b) in-place:          slot IS the object
                    //       *slot           == vtable directly
                    // Try (a) first since it's the common Creation Engine
                    // pattern; fall back to (b) for statically-allocated
                    // singletons like Main / Sky.
                    uintptr_t storage_va = (uintptr_t)image_base_runtime + store_rva;
                    uintptr_t obj_va = 0;
                    bool slot_read_ok = proc::ReadT(a, storage_va, &obj_va);
                    uintptr_t vt_va = 0;
                    bool vt_read_ok = false;
                    if (slot_read_ok && obj_va) {
                        vt_read_ok = proc::ReadT(a, obj_va, &vt_va);
                    }
                    if (diag_seen_rvas.insert(store_rva).second) {
                        diag_candidates.push_back({store_rva, obj_va, vt_va});
                    }
                    bool match_pointer  = slot_read_ok && obj_va && vt_read_ok
                        && valid_vtable_vas.find((uint64_t)vt_va) != valid_vtable_vas.end();
                    bool match_in_place = slot_read_ok
                        && valid_vtable_vas.find((uint64_t)obj_va) != valid_vtable_vas.end();
                    if (!match_pointer && !match_in_place) continue;

                    // Match — accept.
                    Resolved s;
                    s.class_name    = target;
                    s.vtable_rva    = entry->vtable_rva;
                    s.singleton_rva = store_rva;
                    s.ctor_rva      = args.text_rva + (uint32_t)lea_off;
                    out.push_back(s);
                    seen.insert(target);
                    found_one = true;
                    break;
                }
            }
        }
        if (!found_one) {
            dlog::Warn("singletons: no verified storage for '%s' (vtables=%zu lea=%zu cand=%zu distinct=%zu) — may not be instantiated yet",
                       target.c_str(), vec->size(), total_lea_hits,
                       total_candidates, diag_candidates.size());
            // Diagnostic: print the first 12 distinct candidate slots,
            // showing what the live process has at each. Lets us tell
            // null-slot (not constructed) from wrong-vtable (we're picking
            // the wrong RTTI class for the lookup).
            size_t shown = 0;
            for (const auto& c : diag_candidates) {
                if (shown >= 12) break;
                ++shown;
                if (c.obj_va == 0) {
                    dlog::Info("    cand[%2zu] store=0x%X  slot=NULL", shown - 1, c.store_rva);
                } else if (c.vt_va == 0) {
                    dlog::Info("    cand[%2zu] store=0x%X  obj=0x%llX  (vtable read failed)",
                               shown - 1, c.store_rva, (unsigned long long)c.obj_va);
                } else {
                    // What class does this vtable correspond to? Linear scan.
                    const rtti::ClassEntry* hit = nullptr;
                    uint32_t vt_rva = (uint32_t)((uint64_t)c.vt_va - image_base_runtime);
                    for (const auto& e : classes) {
                        if (e.vtable_rva == vt_rva) { hit = &e; break; }
                    }
                    dlog::Info("    cand[%2zu] store=0x%X  obj=0x%llX  vtable=0x%llX  -> %s",
                               shown - 1, c.store_rva,
                               (unsigned long long)c.obj_va,
                               (unsigned long long)c.vt_va,
                               hit ? hit->name.c_str() : "(unknown vtable)");
                }
            }
        }
    }
    dlog::Info("singletons::Find: resolved %zu of %zu targets",
               out.size(), targets.size());
    return true;
}

} // namespace singletons
