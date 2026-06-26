// =============================================================================
//  Skyrim AE 1.6.1170 — game engine dumper.
//
//  Attaches to a running SkyrimSE.exe and produces a complete inventory of
//  every analyzable surface of the binary: PE structure, function table,
//  RTTI class inventory, vtable bindings, and the storage slots of the
//  major Creation Engine singletons.
//
//  Outputs land in ./output/ next to this binary:
//      dumper.log       — consolidated text log of every phase
//      pe_summary.txt   — module identity + section headers
//      sections.csv     — section table machine-readable
//      functions.csv    — .pdata function table (RVA start/end/unwind)
//      classes.csv      — RTTI inventory (one row per class+vtable binding)
//      singletons.csv   — resolved singleton storage RVAs for known classes
//
//  Usage: GHaxSkyrimDumper.exe  (no args; expects SkyrimSE.exe in process list)
// =============================================================================
#include "log.h"
#include "process.h"
#include "pe.h"
#include "pdata.h"
#include "rtti.h"
#include "singletons.h"
#include "getters.h"
#include "data_scan.h"
#include "vtable_dump.h"
#include "hierarchy.h"

#include <Windows.h>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <unordered_set>
#include <vector>
#include <string>

namespace fs = std::filesystem;

static std::wstring ExeDir() {
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    fs::path p = buf;
    return p.parent_path().wstring();
}

static fs::path OutDir() {
    fs::path d = fs::path(ExeDir()) / L"output";
    fs::create_directories(d);
    return d;
}

static void WritePeSummary(const fs::path& path, const pe::ImageInfo& info,
                           const proc::Attached& a) {
    std::ofstream f(path);
    f << "=== Skyrim AE — PE summary ===\n";
    f << "PID                  : " << a.pid << "\n";
    f << "Runtime base         : 0x" << std::hex << a.base << std::dec << "\n";
    f << "Size of image (live) : 0x" << std::hex << a.size << std::dec
      << " (" << (a.size / (1024 * 1024)) << " MiB)\n";
    f << "Preferred base (hdr) : 0x" << std::hex << info.image_base << std::dec << "\n";
    f << "Machine              : 0x" << std::hex << info.machine << std::dec
      << (info.machine == 0x8664 ? "  (x86_64)" : "") << "\n";
    f << "Section count        : " << info.num_sections << "\n";
    f << "Entry RVA            : 0x" << std::hex << info.entry_rva << std::dec << "\n";
    f << "Timestamp            : " << info.timestamp << "\n";
    f << "DllCharacteristics   : 0x" << std::hex << info.dll_chars << std::dec
      << ((info.dll_chars & 0x0040) ? "  (DYNAMIC_BASE)" : "") << "\n\n";
    f << "Sections:\n";
    f << "  name      rva         vsize       chars\n";
    for (const auto& s : info.sections) {
        char line[128];
        snprintf(line, sizeof(line),
                 "  %-8s  0x%08X  0x%08X  0x%08X\n",
                 s.name.c_str(), s.rva, s.vsize, s.chars);
        f << line;
    }
}

static void WriteSectionsCsv(const fs::path& path, const pe::ImageInfo& info) {
    std::ofstream f(path);
    f << "name,rva_hex,vsize_hex,chars_hex\n";
    for (const auto& s : info.sections) {
        char line[128];
        snprintf(line, sizeof(line), "%s,0x%X,0x%X,0x%X\n",
                 s.name.c_str(), s.rva, s.vsize, s.chars);
        f << line;
    }
}

static void WriteFunctionsCsv(const fs::path& path,
                              const std::vector<pdata::Function>& fns) {
    std::ofstream f(path);
    f << "begin_rva,end_rva,unwind_rva,size\n";
    for (const auto& fn : fns) {
        char line[96];
        snprintf(line, sizeof(line), "0x%X,0x%X,0x%X,%u\n",
                 fn.begin_rva, fn.end_rva, fn.unwind_rva, fn.size());
        f << line;
    }
}

static void WriteClassesCsv(const fs::path& path,
                            const std::vector<rtti::ClassEntry>& cls) {
    std::ofstream f(path);
    f << "name,raw_name,type_desc_rva,col_rva,vtable_rva,n_virtuals\n";
    for (const auto& c : cls) {
        f << c.name << "," << c.raw_name << ",";
        char line[64];
        snprintf(line, sizeof(line), "0x%X,0x%X,0x%X,%u\n",
                 c.type_desc_rva, c.col_rva, c.vtable_rva, c.n_virtuals);
        f << line;
    }
}

static void WriteSingletonsCsv(const fs::path& path,
                               const std::vector<singletons::Resolved>& xs) {
    std::ofstream f(path);
    f << "class_name,vtable_rva,singleton_rva,ctor_ref_rva\n";
    for (const auto& s : xs) {
        char line[64];
        snprintf(line, sizeof(line), ",0x%X,0x%X,0x%X\n",
                 s.vtable_rva, s.singleton_rva, s.ctor_rva);
        f << s.class_name << line;
    }
}

static void WriteGettersCsv(const fs::path& path,
                            const std::vector<getters::Resolved>& xs) {
    std::ofstream f(path);
    f << "class_name,pattern,getter_rva,slot_rva,vtable_rva,verified\n";
    for (const auto& g : xs) {
        char line[96];
        snprintf(line, sizeof(line), ",%c,0x%X,0x%X,0x%X,%d\n",
                 g.pattern ? g.pattern : '?',
                 g.getter_rva, g.slot_rva, g.vtable_rva, g.verified ? 1 : 0);
        f << g.class_name << line;
    }
}

int main() {
    SetConsoleTitleW(L"Skyrim Engine Dumper");

    fs::path out = OutDir();
    dlog::Init((out / L"dumper.log").string());
    dlog::Info("==============================================================");
    dlog::Info("Skyrim AE 1.6.1170 — game engine dumper");
    dlog::Info("Output dir: %ls", out.wstring().c_str());
    dlog::Info("==============================================================");

    // ── 1. Attach ────────────────────────────────────────────────────────────
    dlog::Phase("PHASE 1: attach to SkyrimSE.exe");
    proc::Attached a = proc::AttachByModule(L"SkyrimSE.exe");
    if (!a.handle) {
        dlog::Error("Couldn't attach. Make sure the game is running.");
        dlog::Shutdown();
        return 1;
    }

    // ── 2. PE structure ──────────────────────────────────────────────────────
    dlog::Phase("PHASE 2: parse PE headers");
    pe::ImageInfo info;
    if (!pe::ParseImage(a, info)) { dlog::Shutdown(); return 2; }
    WritePeSummary(out / "pe_summary.txt", info, a);
    WriteSectionsCsv(out / "sections.csv", info);
    dlog::Info("PE summary written: %u sections", info.num_sections);

    // ── 3. Read the big sections once (and reuse) ────────────────────────────
    dlog::Phase("PHASE 3: read .text + .rdata + .data into memory");
    std::vector<uint8_t> text_buf, rdata_buf, data_buf;
    bool ok_text  = pe::ReadSection(a, info, ".text",  text_buf);
    bool ok_rdata = pe::ReadSection(a, info, ".rdata", rdata_buf);
    bool ok_data  = pe::ReadSection(a, info, ".data",  data_buf);
    const pe::Section* sec_text  = pe::SectionFromRva(info,
        info.by_name.count(".text") ? info.sections[info.by_name[".text"]].rva : 0);
    // Resolve actual RVAs for the analysis-relevant sections
    uint32_t text_rva = 0, text_size = 0;
    uint32_t rdata_rva = 0, rdata_size = 0;
    uint32_t data_rva = 0, data_size = 0;
    for (const auto& s : info.sections) {
        if (s.name == ".text"  && text_rva  == 0) { text_rva  = s.rva; text_size  = s.vsize; }
        if (s.name == ".rdata" && rdata_rva == 0) { rdata_rva = s.rva; rdata_size = s.vsize; }
        if (s.name == ".data"  && data_rva  == 0) { data_rva  = s.rva; data_size  = s.vsize; }
    }
    dlog::Info(".text  rva=0x%X size=0x%X  read_full=%d buf=%zu", text_rva, text_size, ok_text, text_buf.size());
    dlog::Info(".rdata rva=0x%X size=0x%X  read_full=%d buf=%zu", rdata_rva, rdata_size, ok_rdata, rdata_buf.size());
    dlog::Info(".data  rva=0x%X size=0x%X  read_full=%d buf=%zu", data_rva, data_size, ok_data, data_buf.size());

    // Diagnostic hex/string sampling — proves our buffers contain real data
    // and lets us eyeball whether SteamStub left encrypted bytes anywhere
    // we still care about.
    auto sample = [](const char* label, const std::vector<uint8_t>& buf) {
        char hex[160] = {};
        size_t n = buf.size() < 32 ? buf.size() : 32;
        for (size_t i = 0; i < n; ++i) {
            snprintf(hex + i * 3, 4, "%02X ", buf[i]);
        }
        dlog::Info("  %s first 32B: %s", label, hex);

        // Count printable runs of length >= 8.
        size_t runs = 0, longest = 0, cur = 0;
        for (uint8_t b : buf) {
            if (b >= 0x20 && b < 0x7F) {
                ++cur;
                if (cur > longest) longest = cur;
            } else {
                if (cur >= 8) ++runs;
                cur = 0;
            }
        }
        if (cur >= 8) ++runs;
        dlog::Info("  %s printable runs >=8: %zu  longest=%zu",
                   label, runs, longest);
    };
    sample(".text ", text_buf);
    sample(".rdata", rdata_buf);
    sample(".data ", data_buf);

    // String survey — dump the first 40 long printable runs from .rdata so
    // we can verify what's actually in there. If we see "TESForm", "Actor"
    // etc as standalone strings, the binary has Bethesda's debug strings
    // even if RTTI mangled names are stripped — that's our anchor.
    {
        dlog::Info("─── .rdata long-string sample (first 40 runs len>=12) ───");
        size_t shown = 0;
        size_t cur_start = 0;
        bool in_run = false;
        for (size_t i = 0; i < rdata_buf.size() && shown < 40; ++i) {
            uint8_t b = rdata_buf[i];
            bool printable = (b >= 0x20 && b < 0x7F);
            if (printable && !in_run) { in_run = true; cur_start = i; }
            else if (!printable && in_run) {
                in_run = false;
                size_t len = i - cur_start;
                if (len >= 12) {
                    std::string s((const char*)&rdata_buf[cur_start], len);
                    if (s.size() > 120) s.resize(120);
                    dlog::Info("  [0x%08X +%zu] %s",
                               (uint32_t)(rdata_rva + cur_start), len, s.c_str());
                    ++shown;
                }
            }
        }
        if (shown == 0) dlog::Info("  (no runs len>=12 found in scanned range)");
    }

    // Count substring hits for several known marker patterns. This tells us
    // immediately whether RTTI was stripped, encrypted, or just present in
    // a different format than I expected.
    {
        struct Pat { const char* name; const uint8_t* needle; size_t len; };
        const uint8_t n_av[]   = {'.','?','A','V'};
        const uint8_t n_au[]   = {'.','?','A','U'};
        const uint8_t n_avwq[] = {'.','?','A'};               // wildcard prefix
        const uint8_t n_tesf[] = {'T','E','S','F','o','r','m'};
        const uint8_t n_actor[]= {'A','c','t','o','r'};
        const uint8_t n_player[] = {'P','l','a','y','e','r','C','h','a','r','a','c','t','e','r'};
        const uint8_t n_dragn[]  = {'D','r','a','g','o','n','b','o','r','n'};
        const uint8_t n_whtr[]   = {'W','h','i','t','e','r','u','n'};
        Pat pats[] = {
            {".?AV",            n_av,     4},
            {".?AU",            n_au,     4},
            {".?A",             n_avwq,   3},
            {"TESForm",         n_tesf,   7},
            {"Actor",           n_actor,  5},
            {"PlayerCharacter", n_player, 15},
            {"Dragonborn",      n_dragn,  10},
            {"Whiterun",        n_whtr,   8},
        };
        dlog::Info("─── substring hit counts ───");
        for (const auto& p : pats) {
            size_t rdata_n = 0, data_n = 0;
            for (size_t i = 0; i + p.len <= rdata_buf.size(); ++i)
                if (memcmp(&rdata_buf[i], p.needle, p.len) == 0) ++rdata_n;
            for (size_t i = 0; i + p.len <= data_buf.size(); ++i)
                if (memcmp(&data_buf[i], p.needle, p.len) == 0) ++data_n;
            dlog::Info("  %-18s  .rdata=%-6zu  .data=%zu", p.name, rdata_n, data_n);
        }
    }

    // ── 4. .pdata function table ─────────────────────────────────────────────
    dlog::Phase("PHASE 4: walk .pdata function table");
    std::vector<pdata::Function> fns;
    pdata::Walk(a, info, fns);
    auto pstats = pdata::Summarize(fns);
    dlog::Info("Functions: %zu  total=%u bytes  min=%u  mean=%u  max=%u",
               pstats.count, pstats.total_bytes,
               pstats.min_size, pstats.mean_size, pstats.max_size);
    WriteFunctionsCsv(out / "functions.csv", fns);

    // ── 5. RTTI inventory ────────────────────────────────────────────────────
    dlog::Phase("PHASE 5: walk RTTI (TypeDescriptor -> COL -> vtable)");
    std::vector<rtti::ClassEntry> classes;
    rtti::WalkArgs wargs;
    wargs.rdata_bytes = &rdata_buf;
    wargs.text_bytes  = &text_buf;
    wargs.data_bytes  = &data_buf;
    wargs.rdata_rva   = rdata_rva;
    wargs.text_rva    = text_rva;
    wargs.data_rva    = data_rva;
    rtti::Walk(a, info, wargs, classes);
    dlog::Info("RTTI: %zu (class, vtable) bindings", classes.size());
    WriteClassesCsv(out / "classes.csv", classes);

    // Print a few well-known anchors so we can eyeball correctness immediately.
    {
        rtti::Index idx; idx.Build(classes);
        const char* anchors[] = {
            "PlayerCharacter", "Actor", "TESObjectREFR", "TESForm",
            "TESNPC", "Main", "ProcessLists", "TES", "TESDataHandler",
            "PlayerCamera", "ConsoleLog", "MenuManager", "UIManager",
            "BSInputDeviceManager"
        };
        for (const char* n : anchors) {
            auto* vec = idx.FindAllByName(n);
            if (!vec) { dlog::Info("  anchor %-22s : NOT FOUND", n); continue; }
            for (const auto* e : *vec) {
                dlog::Info("  anchor %-22s : vtable=0x%X  vfuncs=%u",
                           n, e->vtable_rva, e->n_virtuals);
            }
        }
    }

    // ── 6. Singleton storage discovery ───────────────────────────────────────
    dlog::Phase("PHASE 6: locate singleton storage slots");
    std::vector<singletons::Resolved> sings;
    singletons::Args sargs;
    sargs.text_bytes  = &text_buf;
    sargs.rdata_bytes = &rdata_buf;
    sargs.text_rva    = text_rva;
    sargs.rdata_rva   = rdata_rva;
    sargs.data_rva    = data_rva;
    sargs.data_size   = data_size;
    // Polymorphic singletons only — ProcessLists / TESDataHandler / UIManager
    // are non-virtual and don't have RTTI, so we can't anchor on a vtable.
    // Those need a different discovery path (string-xref or known
    // GetSingleton call patterns) — out of scope for v1 dumper.
    std::vector<std::string> targets = {
        "PlayerCharacter", "Main", "TES", "Sky",
        "PlayerCamera", "Console", "MenuControls",
        "MenuTopicManager", "BGSStoryTeller"
    };
    singletons::Find(a, info, classes, sargs, targets, sings);
    WriteSingletonsCsv(out / "singletons.csv", sings);
    for (const auto& s : sings) {
        dlog::Info("  singleton  %-22s  storage=0x%X  vtable=0x%X",
                   s.class_name.c_str(), s.singleton_rva, s.vtable_rva);
    }

    // ── 7. Live verification — read every resolved storage slot and check
    //      it holds a plausible heap pointer to an object whose vtable
    //      pointer matches the RTTI vtable we cataloged. If those match,
    //      we know the singleton storage RVA is correct AND the game has
    //      already constructed the singleton (it has, since we attached
    //      mid-frame).
    dlog::Phase("PHASE 7: live verification");
    int verified = 0;
    for (const auto& s : sings) {
        uintptr_t storage_va = a.base + s.singleton_rva;
        uintptr_t obj_va = 0;
        if (!proc::ReadT(a, storage_va, &obj_va) || !obj_va) {
            dlog::Warn("  verify %-22s  storage=0x%llX -> NULL (not constructed yet?)",
                       s.class_name.c_str(),
                       (unsigned long long)storage_va);
            continue;
        }
        uintptr_t obj_vtable_va = 0;
        if (!proc::ReadT(a, obj_va, &obj_vtable_va)) {
            dlog::Warn("  verify %-22s  obj=0x%llX read failed",
                       s.class_name.c_str(), (unsigned long long)obj_va);
            continue;
        }
        uint64_t expected_vtable_va = (uint64_t)a.base + s.vtable_rva;
        if (obj_vtable_va == expected_vtable_va) {
            dlog::Info("  verify %-22s  obj=0x%llX vtable=MATCH",
                       s.class_name.c_str(), (unsigned long long)obj_va);
            ++verified;
        } else {
            // Multi-vtable classes: the storage may hold a subobject pointer
            // whose vtable is one of the OTHER vtables for this class. Check.
            rtti::Index idx; idx.Build(classes);
            auto* vec = idx.FindAllByName(s.class_name);
            bool alt = false;
            if (vec) for (const auto* e : *vec) {
                if ((uint64_t)a.base + e->vtable_rva == obj_vtable_va) {
                    alt = true; break;
                }
            }
            if (alt) {
                dlog::Info("  verify %-22s  obj=0x%llX vtable=ALT-MATCH (0x%llX)",
                           s.class_name.c_str(),
                           (unsigned long long)obj_va,
                           (unsigned long long)obj_vtable_va);
                ++verified;
            } else {
                dlog::Warn("  verify %-22s  obj=0x%llX vtable=0x%llX (expected 0x%llX) — likely false-positive storage",
                           s.class_name.c_str(),
                           (unsigned long long)obj_va,
                           (unsigned long long)obj_vtable_va,
                           (unsigned long long)expected_vtable_va);
            }
        }
    }
    dlog::Info("verified %d of %zu singletons against live process",
               verified, sings.size());

    // ── 8. Accessor-pattern singleton scan ───────────────────────────────────
    // The ctor-anchored finder misses singletons whose constructors don't
    // emit the `lea; mov [rcx],rax` install pattern (Main, TES, Console,
    // many others). The accessor pattern is invariant: every singleton has
    // a tiny `mov rax, [rip+disp]; ret` getter somewhere in .text.
    dlog::Phase("PHASE 8: getter-pattern singleton scan");
    std::vector<getters::Resolved> getters_out;
    getters::Args gargs;
    gargs.text_bytes = &text_buf;
    gargs.text_rva   = text_rva;
    gargs.data_rva   = data_rva;
    gargs.data_size  = data_size;
    getters::Scan(a, info, classes, gargs, getters_out);
    WriteGettersCsv(out / "getters.csv", getters_out);

    // Print the verified high-value ones for quick eyeballing.
    const char* interesting[] = {
        "PlayerCharacter", "Main", "TES", "Sky", "Console", "PlayerCamera",
        "MenuControls", "MenuTopicManager", "BGSStoryTeller",
        "TESDataHandler", "ProcessLists", "UIManager", "ConsoleLog",
        "MenuManager", "BSInputDeviceManager", "BSGraphics::Renderer",
        "BSScaleformManager", "BGSDefaultObjectManager",
        "TESCombatStyle", "ActorMover"
    };
    for (const char* n : interesting) {
        for (const auto& g : getters_out) {
            if (g.verified && g.class_name == n) {
                dlog::Info("  getter %-30s slot=0x%X  vtable=0x%X  getter@0x%X (pat %c)",
                           g.class_name.c_str(), g.slot_rva, g.vtable_rva,
                           g.getter_rva, g.pattern);
            }
        }
    }

    // ── 9. Exhaustive .data slot resolver ───────────────────────────────────
    // Brute-force every aligned qword in .data; if it points to an object
    // whose vtable matches a class, emit a (slot,class) pair. This catches
    // every singleton / global object pointer regardless of how the engine
    // accesses it — closes the gap on Main / TES / Sky / Console and
    // surfaces dozens of other engine globals as a bonus.
    dlog::Phase("PHASE 9: brute-force .data slot resolver");
    std::vector<data_scan::SlotMatch> slot_matches;
    data_scan::Args dargs;
    dargs.data_bytes = &data_buf;
    dargs.data_rva   = data_rva;
    data_scan::Scan(a, classes, dargs, slot_matches);

    // Write to CSV.
    {
        std::ofstream sf(out / "data_slots.csv");
        sf << "class_name,slot_rva,vtable_rva,obj_va\n";
        for (const auto& m : slot_matches) {
            char line[96];
            snprintf(line, sizeof(line), ",0x%X,0x%X,0x%llX\n",
                     m.slot_rva, m.vtable_rva,
                     (unsigned long long)m.obj_va);
            sf << m.class_name << line;
        }
    }

    // ── 10. Vtable function pointer dump ────────────────────────────────────
    dlog::Phase("PHASE 10: vtable function pointer dump");
    std::vector<vtable_dump::Row> vt_rows;
    vtable_dump::Args vargs;
    vargs.rdata_bytes = &rdata_buf;
    vargs.rdata_rva   = rdata_rva;
    vargs.text_rva    = text_rva;
    vtable_dump::Dump(a, classes, vargs, vt_rows);
    {
        std::ofstream vf(out / "vtables.csv");
        vf << "class_name,vtable_rva,vfunc_idx,vfunc_rva\n";
        for (const auto& r : vt_rows) {
            char line[64];
            snprintf(line, sizeof(line), ",0x%X,%u,0x%X\n",
                     r.vtable_rva, r.vfunc_idx, r.vfunc_rva);
            vf << r.class_name << line;
        }
    }

    // ── 11. Inheritance hierarchy ────────────────────────────────────────────
    dlog::Phase("PHASE 11: walk RTTI ClassHierarchyDescriptor chain");
    std::vector<hierarchy::Row> hier_rows;
    hierarchy::Args hargs;
    hargs.rdata_bytes = &rdata_buf;
    hargs.data_bytes  = &data_buf;
    hargs.rdata_rva   = rdata_rva;
    hargs.data_rva    = data_rva;
    hierarchy::Build(a, classes, hargs, hier_rows);
    {
        std::ofstream hf(out / "hierarchy.csv");
        hf << "class_name,vtable_rva,bases\n";
        for (const auto& r : hier_rows) {
            char hd[64];
            snprintf(hd, sizeof(hd), ",0x%X,", r.vtable_rva);
            hf << r.class_name << hd;
            for (size_t i = 0; i < r.bases.size(); ++i) {
                if (i) hf << "|";
                hf << r.bases[i];
            }
            hf << "\n";
        }
    }
    // Print a few interesting chains.
    for (const auto& r : hier_rows) {
        if (r.class_name == "PlayerCharacter" || r.class_name == "Actor" ||
            r.class_name == "TESObjectREFR"   || r.class_name == "TESForm"  ||
            r.class_name == "TESNPC"          || r.class_name == "Sky"      ||
            r.class_name == "TES"             || r.class_name == "Main"     ||
            r.class_name == "BGSStoryTeller") {
            std::string chain;
            for (size_t i = 0; i < r.bases.size(); ++i) {
                if (i) chain += " <- ";
                chain += r.bases[i];
            }
            dlog::Info("  %-22s %s", r.class_name.c_str(), chain.c_str());
        }
    }

    // Print one slot per high-value class — first match per class.
    {
        std::unordered_set<std::string> shown;
        for (const auto& m : slot_matches) {
            if (shown.count(m.class_name)) continue;
            bool is_interesting = false;
            for (const char* n : interesting) {
                if (m.class_name == n) { is_interesting = true; break; }
            }
            if (!is_interesting) continue;
            shown.insert(m.class_name);
            dlog::Info("  slot %-32s slot=0x%X  vtable=0x%X  obj=0x%llX",
                       m.class_name.c_str(), m.slot_rva, m.vtable_rva,
                       (unsigned long long)m.obj_va);
        }
        // Report which interesting classes still missing.
        for (const char* n : interesting) {
            if (!shown.count(n)) {
                bool exists_in_rtti = false;
                for (const auto& c : classes) {
                    if (c.name == n) { exists_in_rtti = true; break; }
                }
                if (exists_in_rtti) {
                    dlog::Warn("  slot %-32s no .data slot points to an instance (not constructed?)", n);
                } else {
                    dlog::Info("  slot %-32s class has no RTTI entry", n);
                }
            }
        }
    }

    // ── done ─────────────────────────────────────────────────────────────────
    dlog::Phase("DONE");
    dlog::Info("Wrote: pe_summary.txt sections.csv functions.csv classes.csv singletons.csv dumper.log");
    proc::Detach(a);
    dlog::Shutdown();
    return 0;
}
