# Skyrim AE Engine Dumper

Dumper for **The Elder Scrolls V: Skyrim Anniversary Edition** (`SkyrimSE.exe` 1.6.1170.0).

# Dumped:

| Output | Count | Description |
|---|---|---|
| `functions.csv` | 120,080 | Every function in `.text` (RVA range + unwind info from `.pdata`) |
| `classes.csv` | 8,447 | Every RTTI class + vtable binding |
| `vtables.csv` | 88,861 | Every vfunc slot `(class, vtable_rva, idx, vfunc_rva)` |
| `hierarchy.csv` | 8,447 | Inheritance chains via `ClassHierarchyDescriptor` walk |
| `data_slots.csv` | 71,477 | Every `.data` slot holding a class-object pointer, matched live |
| `getters.csv` | 83 | `GetSingleton()` accessor pattern hits |
| `singletons.csv` | 5 | Constructor-anchored verified singletons |
| `sections.csv` | 9 | PE section table |
| `pe_summary.txt` | | Human-readable module identity |
| `dumper.log` | | Phase-by-phase consolidated log |

A singleton generally refers to a single, unique entity distinct from a group or pair, with its specific meaning depending on the context. 

All resolved against a live process slot is read, dereferenced, and the resulting object's vtable is confirmed against the RTTI catalog before being emitted.

# Key implementation notes

- **TypeDescriptors are in `.data`**, not `.rdata`. The `type_info` vtable pointer at TD+0 needs to be runtime-initialized, forcing the writable section. Scanners that only check `.rdata` find zero.
- **Vtable references in x64 code are LEA RIP-relative** (`48 8D 05 disp32`), never 8-byte absolute immediates.
- **The "first store after vtable LEA" heuristic gives ~50% false positives.** Reading the candidate from live memory and matching the deref'd vtable is the only reliable signal.
- **SteamStub never gets unpacked**. We work entirely against the runtime-decrypted image in process memory same view the trainer will use.

# Build

Requires Visual Studio 2022 Build Tools, CMake 3.20+. C++17, no dependencies.

```cmd
build.cmd
```

Produces `build\Release\GHaxSkyrimDumper.exe`.
