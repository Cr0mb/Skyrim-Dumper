// =============================================================================
//  process.h — attach to a running Win32 process, find a named module, and
//  expose a thin Read() wrapper.
//
//  No driver involved (this is a userland dumper running with the same
//  privileges as the game). PROCESS_VM_READ + PROCESS_QUERY_INFORMATION is
//  enough for everything below; we never write.
// =============================================================================
#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace proc {

struct Attached {
    HANDLE     handle = nullptr;
    DWORD      pid    = 0;
    uintptr_t  base   = 0;     // module base address in the target process
    size_t     size   = 0;     // SizeOfImage
};

// Find PID of first process with the given basename (e.g. L"SkyrimSE.exe").
DWORD FindPidByName(const wchar_t* basename);

// Open the process and locate the named module. Returns Attached with non-zero
// handle on success.
Attached AttachByModule(const wchar_t* moduleName);

// Read `len` bytes at absolute address `va`. Returns true and fills `out`
// on full read; false on partial / failure.
bool Read(const Attached& a, uintptr_t va, void* out, size_t len);

// Convenience: read sized buffer rooted at module base + RVA.
inline bool ReadRva(const Attached& a, uint32_t rva, void* out, size_t len) {
    return Read(a, a.base + rva, out, len);
}

template <class T>
inline bool ReadT(const Attached& a, uintptr_t va, T* out) {
    return Read(a, va, out, sizeof(T));
}

// Pull an entire byte range (e.g. a whole PE section) into a vector. On
// partial reads we keep what we got and return false; caller can decide
// whether to use the truncated buffer.
bool ReadRange(const Attached& a, uintptr_t va, size_t len, std::vector<uint8_t>& out);

void Detach(Attached& a);

} // namespace proc
