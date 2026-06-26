#include "hierarchy.h"
#include "log.h"

#include <cstring>
#include <unordered_map>

namespace hierarchy {

namespace {

// Read a uint32 at an absolute RVA via the appropriate section buffer.
// Returns false if the RVA is outside the buffer.
template <class T>
bool ReadFromBuf(const std::vector<uint8_t>& buf, uint32_t buf_rva,
                 uint32_t rva, T* out) {
    if (rva < buf_rva) return false;
    size_t off = (size_t)(rva - buf_rva);
    if (off + sizeof(T) > buf.size()) return false;
    std::memcpy(out, &buf[off], sizeof(T));
    return true;
}

// Demangle ".?AVName@@" -> "Name" (same heuristic as rtti.cpp).
std::string Demangle(const std::string& raw) {
    if (raw.size() < 6) return raw;
    if (raw.compare(0, 4, ".?AV") != 0 && raw.compare(0, 4, ".?AU") != 0)
        return raw;
    std::string body = raw.substr(4);
    while (body.size() >= 2 && body.substr(body.size() - 2) == "@@") {
        body.resize(body.size() - 2);
    }
    if (body.find('@') == std::string::npos) return body;
    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos <= body.size()) {
        size_t at = body.find('@', pos);
        if (at == std::string::npos) { parts.push_back(body.substr(pos)); break; }
        parts.push_back(body.substr(pos, at - pos));
        pos = at + 1;
    }
    std::string out;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        if (it->empty()) continue;
        if (!out.empty()) out += "::";
        out += *it;
    }
    return out.empty() ? body : out;
}

// Read the TypeDescriptor's name field given its RVA in .data.
std::string ReadTypeDescName(const std::vector<uint8_t>& data, uint32_t data_rva,
                              uint32_t td_rva) {
    if (td_rva < data_rva) return "";
    size_t off = (size_t)(td_rva - data_rva);
    // Name field is at TD+0x10.
    if (off + 0x10 > data.size()) return "";
    size_t name_off = off + 0x10;
    size_t end = name_off;
    const size_t lim = (name_off + 256 < data.size()) ? (name_off + 256) : data.size();
    while (end < lim && data[end] != 0) ++end;
    return std::string((const char*)&data[name_off], end - name_off);
}

} // anon

bool Build(const proc::Attached& a,
           const std::vector<rtti::ClassEntry>& classes,
           const Args& args,
           std::vector<Row>& out) {
    if (!args.rdata_bytes || args.rdata_bytes->empty() ||
        !args.data_bytes  || args.data_bytes->empty()) {
        dlog::Error("hierarchy: rdata or data buffer missing");
        return false;
    }
    const auto& rdata = *args.rdata_bytes;
    const auto& data  = *args.data_bytes;

    size_t emitted = 0, skipped = 0;
    for (const auto& c : classes) {
        // COL is at c.col_rva in .rdata.
        //   +0x10 = ClassHierarchyDescriptor RVA
        uint32_t chd_rva = 0;
        if (!ReadFromBuf(rdata, args.rdata_rva, c.col_rva + 0x10, &chd_rva)) {
            ++skipped; continue;
        }
        // CHD is in .rdata.
        //   +0x08 = num_bases
        //   +0x0C = pBaseClassArray (RVA)
        uint32_t n_bases = 0, bc_arr_rva = 0;
        if (!ReadFromBuf(rdata, args.rdata_rva, chd_rva + 0x08, &n_bases)) { ++skipped; continue; }
        if (!ReadFromBuf(rdata, args.rdata_rva, chd_rva + 0x0C, &bc_arr_rva)) { ++skipped; continue; }
        if (n_bases == 0 || n_bases > 64) { ++skipped; continue; }

        Row row;
        row.class_name = c.name;
        row.col_rva    = c.col_rva;
        row.vtable_rva = c.vtable_rva;
        row.bases.reserve(n_bases);

        for (uint32_t i = 0; i < n_bases; ++i) {
            uint32_t bcd_rva = 0;
            if (!ReadFromBuf(rdata, args.rdata_rva, bc_arr_rva + i * 4, &bcd_rva)) break;
            // BCD's first field is pTypeDescriptor (RVA into .data).
            uint32_t td_rva = 0;
            if (!ReadFromBuf(rdata, args.rdata_rva, bcd_rva, &td_rva)) break;
            std::string raw = ReadTypeDescName(data, args.data_rva, td_rva);
            if (raw.empty()) continue;
            row.bases.push_back(Demangle(raw));
        }

        if (!row.bases.empty()) {
            out.push_back(std::move(row));
            ++emitted;
        } else {
            ++skipped;
        }
    }
    dlog::Info("hierarchy: built chains for %zu classes (skipped %zu)",
               emitted, skipped);
    return true;
}

} // namespace hierarchy
