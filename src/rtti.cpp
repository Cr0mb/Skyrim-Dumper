#include "rtti.h"
#include "log.h"

#include <Windows.h>
#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace rtti {

namespace {

// MSVC mangled name to a friendly string.
//   ".?AVTESForm@@"       -> "TESForm"
//   ".?AVMy@Nested@@"     -> "Nested::My"   (best-effort; we don't fully demangle)
//   ".?AU<struct>@@"      -> "<struct>"
std::string Demangle(const std::string& raw) {
    if (raw.size() < 6) return raw;
    if (raw.compare(0, 4, ".?AV") != 0 && raw.compare(0, 4, ".?AU") != 0)
        return raw;
    // strip leading 4 chars, strip trailing "@@"
    std::string body = raw.substr(4);
    while (body.size() >= 2 && body.substr(body.size() - 2) == "@@") {
        body.resize(body.size() - 2);
    }
    // Nested namespaces are separated by '@' in reverse order.
    // ".?AVB@A@@"  means A::B  (outer first, inner last in mangled form).
    if (body.find('@') == std::string::npos) return body;
    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos <= body.size()) {
        size_t at = body.find('@', pos);
        if (at == std::string::npos) {
            parts.push_back(body.substr(pos));
            break;
        }
        parts.push_back(body.substr(pos, at - pos));
        pos = at + 1;
    }
    // Reverse and join with ::
    std::reverse(parts.begin(), parts.end());
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (!parts[i].empty()) {
            if (!out.empty()) out += "::";
            out += parts[i];
        }
    }
    return out.empty() ? body : out;
}

// Find all byte offsets in `hay` where `needle` occurs.
void FindAllOf(const uint8_t* hay, size_t hay_len,
               const uint8_t* needle, size_t needle_len,
               std::vector<size_t>& out) {
    if (needle_len == 0 || needle_len > hay_len) return;
    // Naive scan — needle is short (4 bytes for ".?AV"). For tens of MB this
    // takes a few hundred ms — fine for a one-shot dumper.
    const uint8_t first = needle[0];
    for (size_t i = 0; i + needle_len <= hay_len; ++i) {
        if (hay[i] == first && memcmp(hay + i, needle, needle_len) == 0) {
            out.push_back(i);
        }
    }
}

// Scan a byte buffer for occurrences of a 4-byte uint32 value (DWORD-aligned
// matches only — RTTI fields are aligned).
void FindAllU32Aligned(const std::vector<uint8_t>& buf, uint32_t v,
                       std::vector<size_t>& out) {
    const size_t end = buf.size() & ~size_t(3);
    const uint32_t* p = reinterpret_cast<const uint32_t*>(buf.data());
    const size_t   n = end / 4;
    for (size_t i = 0; i < n; ++i) {
        if (p[i] == v) out.push_back(i * 4);
    }
}

// Same for 8-byte uint64 (vtable[-1] absolute pointer).
void FindAllU64Aligned(const std::vector<uint8_t>& buf, uint64_t v,
                       std::vector<size_t>& out) {
    const size_t end = buf.size() & ~size_t(7);
    const uint64_t* p = reinterpret_cast<const uint64_t*>(buf.data());
    const size_t   n = end / 8;
    for (size_t i = 0; i < n; ++i) {
        if (p[i] == v) out.push_back(i * 8);
    }
}

bool RvaInText(uint32_t rva, uint32_t text_rva, uint32_t text_size) {
    return rva >= text_rva && rva < text_rva + text_size;
}

} // anon

bool Walk(const proc::Attached& a, const pe::ImageInfo& info,
          const WalkArgs& args, std::vector<ClassEntry>& out) {
    if (!args.rdata_bytes || args.rdata_bytes->empty()) {
        dlog::Error("rtti::Walk: rdata buffer missing");
        return false;
    }
    if (!args.data_bytes || args.data_bytes->empty()) {
        dlog::Error("rtti::Walk: data buffer missing (TypeDescriptors live here)");
        return false;
    }
    const auto& rdata = *args.rdata_bytes;
    const auto& data  = *args.data_bytes;
    const uint32_t rdata_rva = args.rdata_rva;
    const uint32_t data_rva  = args.data_rva;
    const uint32_t text_rva  = args.text_rva;
    const uint32_t text_size = args.text_bytes ? (uint32_t)args.text_bytes->size() : 0;

    // ── Phase 1: locate every .?AV / .?AU TypeDescriptor name in .data ─────
    std::vector<size_t> name_hits;
    {
        const uint8_t needle1[] = {'.', '?', 'A', 'V'};
        const uint8_t needle2[] = {'.', '?', 'A', 'U'};
        FindAllOf(data.data(), data.size(), needle1, 4, name_hits);
        FindAllOf(data.data(), data.size(), needle2, 4, name_hits);
    }
    dlog::Info("rtti: phase1 mangled-name hits (in .data): %zu", name_hits.size());

    // Each name hit might or might not be a real TypeDescriptor name. Filter:
    // - name is a NUL-terminated ASCII string of reasonable length
    // - 0x10 bytes before the name, there's a TypeDescriptor header — the
    //   first 8 bytes are a pointer that all type descs share (`type_info`
    //   vtable). We don't need to validate the pointer value (cross-module);
    //   we just require those 8 bytes to be non-zero and "look like" a
    //   pointer (kernel-or-user range, low 4 bits zero is common but not
    //   guaranteed; just require non-zero and that the +8 spare is zero).

    struct TypeDesc {
        uint32_t    rva;          // RVA of TypeDescriptor base (vtable ptr)
        std::string raw_name;     // ".?AV...@@"
    };
    std::vector<TypeDesc> type_descs;
    type_descs.reserve(name_hits.size());

    // Map TypeDescriptor RVA -> index in type_descs (for fast COL lookup).
    std::unordered_map<uint32_t, size_t> td_by_rva;

    for (size_t off : name_hits) {
        // Read the name from .data (bounded by first NUL or 256 chars).
        size_t end = off;
        const size_t maxlen = 256;
        const size_t lim = (data.size() < off + maxlen) ? data.size() : (off + maxlen);
        while (end < lim && data[end] != 0) ++end;
        if (end == off) continue;
        std::string raw((const char*)&data[off], end - off);
        // basic sanity: must end with @@ for a class/struct
        if (raw.size() < 6) continue;
        if (raw[raw.size() - 1] != '@' || raw[raw.size() - 2] != '@') continue;

        // Compute TypeDescriptor base offset in the .data buffer.
        // name field is at TypeDesc + 0x10. So base = off - 0x10.
        if (off < 0x10) continue;
        size_t td_off = off - 0x10;
        // +0 vtable ptr (non-zero), +8 spare (zero)
        uint64_t vptr  = *reinterpret_cast<const uint64_t*>(&data[td_off]);
        uint64_t spare = *reinterpret_cast<const uint64_t*>(&data[td_off + 8]);
        if (vptr == 0 || spare != 0) continue;
        uint32_t td_rva = data_rva + (uint32_t)td_off;

        TypeDesc td{ td_rva, raw };
        td_by_rva[td_rva] = type_descs.size();
        type_descs.push_back(std::move(td));
    }
    dlog::Info("rtti: phase2 valid TypeDescriptors: %zu", type_descs.size());

    // ── Phase 3: COL discovery — find 4-byte references to each TypeDescriptor
    // RVA, back up 0xC bytes, check signature/self-RVA, that's a COL.
    struct ColRecord {
        uint32_t rva;           // COL RVA
        uint32_t td_rva;        // TypeDescriptor RVA
        size_t   td_index;      // index into type_descs
    };
    std::vector<ColRecord> cols;
    cols.reserve(type_descs.size());

    for (size_t i = 0; i < type_descs.size(); ++i) {
        const uint32_t td_rva = type_descs[i].rva;
        std::vector<size_t> refs;
        FindAllU32Aligned(rdata, td_rva, refs);
        for (size_t r : refs) {
            // r is the file offset of a uint32 == td_rva. The COL's +0xC field
            // contains this. COL_base_off = r - 0xC.
            if (r < 0xC) continue;
            size_t col_off = r - 0xC;
            if (col_off + 0x18 > rdata.size()) continue;
            uint32_t sig      = *reinterpret_cast<const uint32_t*>(&rdata[col_off + 0x00]);
            uint32_t self_rva = *reinterpret_cast<const uint32_t*>(&rdata[col_off + 0x14]);
            uint32_t col_rva  = rdata_rva + (uint32_t)col_off;
            if (sig != 1) continue;             // x64 COL signature
            if (self_rva != col_rva) continue;  // self-RVA must match
            cols.push_back({ col_rva, td_rva, i });
        }
    }
    dlog::Info("rtti: phase3 Complete Object Locators: %zu", cols.size());

    // ── Phase 4: vtable discovery — each COL's absolute address shows up in
    // .rdata as the 8-byte vtable[-1] slot. Search for it. Then count
    // virtuals by walking forward until a pointer no longer lands in .text.
    const uint64_t image_base_runtime = (uint64_t)a.base;
    out.reserve(cols.size());

    for (const auto& c : cols) {
        const uint64_t col_abs = image_base_runtime + c.rva;
        std::vector<size_t> vt_minus1;
        FindAllU64Aligned(rdata, col_abs, vt_minus1);

        for (size_t vm1_off : vt_minus1) {
            // vtable starts at vm1_off + 8 (in rdata buffer offset terms)
            size_t vt_off = vm1_off + 8;
            if (vt_off + 8 > rdata.size()) continue;

            // Count virtuals: walk forward in 8-byte strides; pointer must be
            // (absolute) within .text. Stop on first miss.
            uint32_t n = 0;
            while (vt_off + 8 <= rdata.size()) {
                uint64_t ptr = *reinterpret_cast<const uint64_t*>(&rdata[vt_off]);
                if (ptr < image_base_runtime) break;
                uint64_t r = ptr - image_base_runtime;
                if (r > 0xFFFFFFFFu) break;
                uint32_t rva = (uint32_t)r;
                if (!RvaInText(rva, text_rva, text_size)) break;
                ++n;
                vt_off += 8;
                if (n > 2000) break; // safety
            }

            ClassEntry e;
            e.raw_name      = type_descs[c.td_index].raw_name;
            e.name          = Demangle(e.raw_name);
            e.type_desc_rva = c.td_rva;
            e.col_rva       = c.rva;
            e.vtable_rva    = rdata_rva + (uint32_t)(vm1_off + 8);
            e.n_virtuals    = n;
            out.push_back(std::move(e));
        }
    }
    dlog::Info("rtti: phase4 vtable bindings emitted: %zu", out.size());

    // Sort for deterministic output: by class name, then vtable rva.
    std::sort(out.begin(), out.end(), [](const ClassEntry& a, const ClassEntry& b) {
        if (a.name != b.name) return a.name < b.name;
        return a.vtable_rva < b.vtable_rva;
    });
    return true;
}

// ── Index ───────────────────────────────────────────────────────────────────
void Index::Build(const std::vector<ClassEntry>& entries) {
    m_by_name.clear();
    for (const auto& e : entries) m_by_name[e.name].push_back(&e);
}
const ClassEntry* Index::FindByName(const std::string& n) const {
    auto it = m_by_name.find(n);
    return (it == m_by_name.end() || it->second.empty()) ? nullptr : it->second[0];
}
const std::vector<const ClassEntry*>* Index::FindAllByName(const std::string& n) const {
    auto it = m_by_name.find(n);
    return (it == m_by_name.end()) ? nullptr : &it->second;
}

} // namespace rtti
