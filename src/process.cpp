#include "process.h"
#include "log.h"

#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>

#pragma comment(lib, "psapi.lib")

namespace proc {

DWORD FindPidByName(const wchar_t* basename) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, basename) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

Attached AttachByModule(const wchar_t* moduleName) {
    Attached a{};
    a.pid = FindPidByName(moduleName);
    if (!a.pid) {
        dlog::Error("AttachByModule: process '%ls' not found — launch the game first", moduleName);
        return a;
    }
    a.handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, a.pid);
    if (!a.handle) {
        dlog::Error("AttachByModule: OpenProcess(pid=%lu) failed err=%lu",
                    a.pid, GetLastError());
        return a;
    }

    // EnumProcessModulesEx — pick the first module whose basename matches.
    HMODULE mods[1024];
    DWORD cbNeeded = 0;
    if (!EnumProcessModulesEx(a.handle, mods, sizeof(mods), &cbNeeded, LIST_MODULES_64BIT)) {
        dlog::Error("AttachByModule: EnumProcessModulesEx failed err=%lu", GetLastError());
        CloseHandle(a.handle); a.handle = nullptr; return a;
    }
    DWORD nMods = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < nMods; ++i) {
        wchar_t name[MAX_PATH] = {};
        if (GetModuleBaseNameW(a.handle, mods[i], name, MAX_PATH)) {
            if (_wcsicmp(name, moduleName) == 0) {
                MODULEINFO mi{};
                if (GetModuleInformation(a.handle, mods[i], &mi, sizeof(mi))) {
                    a.base = (uintptr_t)mi.lpBaseOfDll;
                    a.size = mi.SizeOfImage;
                }
                break;
            }
        }
    }
    if (!a.base) {
        dlog::Error("AttachByModule: module '%ls' not found in pid=%lu", moduleName, a.pid);
        CloseHandle(a.handle); a.handle = nullptr;
        return a;
    }
    dlog::Info("Attached pid=%lu base=0x%llX size=0x%llX (%llu MiB)",
               a.pid,
               (unsigned long long)a.base,
               (unsigned long long)a.size,
               (unsigned long long)(a.size / (1024 * 1024)));
    return a;
}

bool Read(const Attached& a, uintptr_t va, void* out, size_t len) {
    if (!a.handle || !va || !out || !len) return false;
    SIZE_T got = 0;
    BOOL ok = ReadProcessMemory(a.handle, (LPCVOID)va, out, len, &got);
    return ok && got == len;
}

bool ReadRange(const Attached& a, uintptr_t va, size_t len, std::vector<uint8_t>& out) {
    out.assign(len, 0);
    if (!a.handle || !va || !len) return false;

    // Skyrim's .text + .rdata are ~33 MiB — ReadProcessMemory of that whole
    // span in one call is fine on modern Windows, but if any page in the
    // range is unmapped (rare for image pages) the entire call fails. Chunk
    // by 1 MiB so a single bad page only zeros that chunk.
    constexpr size_t kChunk = 1u << 20;
    size_t done = 0;
    bool any = false, all = true;
    while (done < len) {
        size_t want = (len - done) < kChunk ? (len - done) : kChunk;
        SIZE_T got = 0;
        if (ReadProcessMemory(a.handle, (LPCVOID)(va + done), out.data() + done, want, &got)
            && got == want) {
            any = true;
        } else {
            all = false;
            // leave zeros in this chunk
        }
        done += want;
    }
    return any && all;
}

void Detach(Attached& a) {
    if (a.handle) { CloseHandle(a.handle); a.handle = nullptr; }
    a.pid = 0; a.base = 0; a.size = 0;
}

} // namespace proc
