#include "pdata.h"
#include "log.h"

#include <Windows.h>

namespace pdata {

bool Walk(const proc::Attached& a, const pe::ImageInfo& info,
          std::vector<Function>& out) {
    const pe::Section* sec = nullptr;
    for (const auto& s : info.sections) {
        if (s.name == ".pdata") { sec = &s; break; }
    }
    if (!sec) {
        dlog::Error("pdata::Walk: no .pdata section");
        return false;
    }

    std::vector<uint8_t> buf;
    if (!proc::ReadRange(a, a.base + sec->rva, sec->vsize, buf)) {
        dlog::Warn("pdata::Walk: partial read of .pdata (kept %zu bytes)", buf.size());
    }

    // Each RUNTIME_FUNCTION is 3 x uint32. Iterate, skipping zero rows
    // (.pdata may be padded at the end with zeros).
    const size_t n_rows = buf.size() / sizeof(RUNTIME_FUNCTION);
    out.reserve(n_rows);
    for (size_t i = 0; i < n_rows; ++i) {
        const RUNTIME_FUNCTION* rf =
            reinterpret_cast<const RUNTIME_FUNCTION*>(buf.data() + i * sizeof(RUNTIME_FUNCTION));
        if (rf->BeginAddress == 0 && rf->EndAddress == 0) continue;
        Function f;
        f.begin_rva  = rf->BeginAddress;
        f.end_rva    = rf->EndAddress;
        f.unwind_rva = rf->UnwindInfoAddress;
        out.push_back(f);
    }
    dlog::Info("pdata::Walk: %zu RUNTIME_FUNCTION entries from %u bytes",
               out.size(), sec->vsize);
    return true;
}

Stats Summarize(const std::vector<Function>& fns) {
    Stats s{};
    s.count = fns.size();
    if (fns.empty()) return s;
    uint64_t sum = 0;
    for (const auto& f : fns) {
        uint32_t sz = f.size();
        sum += sz;
        if (sz < s.min_size) s.min_size = sz;
        if (sz > s.max_size) s.max_size = sz;
    }
    s.total_bytes = (uint32_t)sum;
    s.mean_size = (uint32_t)(sum / fns.size());
    return s;
}

} // namespace pdata
