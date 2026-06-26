# Skyrim AE Engine Dumper

A live-memory dumper for **The Elder Scrolls V: Skyrim Anniversary Edition** (`SkyrimSE.exe` 1.6.1170.0). Attaches to the running game and produces a complete inventory of every analyzable surface of the binary — without unpacking the SteamStub DRM, without injecting a DLL, without writing to game memory.

Built to bootstrap external-trainer development: produces verified singleton pointers, full RTTI catalog, function tables, and inheritance graphs that the trainer consumes at startup.

## What it dumps

| Output | Count | Description |
|---|---|---|
| `functions.csv` | 120,080 | Every function in `.text` (RVA range + unwind info from `.pdata`) |
| `classes.csv` | 8,447 | Every RTTI class + vtable binding |
| `vtables.csv` | 88,861 | Every vfunc slot — `(class, vtable_rva, idx, vfunc_rva)` |
| `hierarchy.csv` | 8,447 | Inheritance chains via `ClassHierarchyDescriptor` walk |
| `data_slots.csv` | 71,477 | Every `.data` slot holding a class-object pointer, matched live |
| `getters.csv` | 83 | `GetSingleton()` accessor pattern hits |
| `singletons.csv` | 5 | Constructor-anchored verified singletons |
| `sections.csv` | 9 | PE section table |
| `pe_summary.txt` | — | Human-readable module identity |
| `dumper.log` | — | Phase-by-phase consolidated log |

## Verified singletons

All resolved against a live process — slot is read, dereferenced, and the resulting object's vtable is confirmed against the RTTI catalog before being emitted.

| Class | Slot RVA | Vtable RVA |
|---|---|---|
| `PlayerCharacter` | `0x3137698` | `0x18AB9C0` |
| `PlayerCamera` | `0x30FD7F8` | `0x18EF278` |
| `MenuControls` | `0x31380E8` | `0x18FD550` |
| `MenuTopicManager` | `0x3137778` | `0x1883FE0` |
| `BGSStoryTeller` | `0x20FBA78` | `0x186E890` |
| `Main` | `0x31872C0` | `0x18964B0` |
| `TES` | `0x20F8930` | `0x177AA60` |
| `Sky` | `0x31390E0` | `0x17EFE38` |
| `TESQuest` | `0x20F6010` | `0x17E6A40` |
| `TESWeather` | `0x20F5BE8` | `0x17B1BE8` |
| `TESCombatStyle` | `0x20F5718` | `0x17970B8` |

## How it works

11 phases:

1. **Attach** — `OpenProcess` + `EnumProcessModulesEx` to locate `SkyrimSE.exe`
2. **PE parse** — read the in-memory headers (no on-disk file-offset math; loader already laid it out)
3. **Bulk section read** — pull `.text` / `.rdata` / `.data` into local buffers via chunked `ReadProcessMemory`
4. **`.pdata` walk** — `RUNTIME_FUNCTION` table is the function inventory; Skyrim has no exports so this is the only source
5. **RTTI walk** — find every `.?AV` / `.?AU` mangled name in `.data` (TypeDescriptors live there on this MSVC build), backtrack to `CompleteObjectLocator`s in `.rdata`, locate vtables via `vtable[-1]`
6. **Constructor-anchored singleton scan** — find the unambiguous 10-byte `lea rax, [vtable]; mov [rcx], rax` prologue, scan forward for the singleton-store mov
7. **Live verification** — read each candidate slot from the running process; accept only if the deref'd object's vtable matches one of the class's cataloged vtables
8. **Getter-pattern scan** — find tiny `GetSingleton()` accessor functions (`mov rax, [rip+disp]; ret` — 8 bytes)
9. **Brute-force `.data` slot resolver** — for every aligned qword in `.data`, deref once via live `RPM` and check whether the resulting vtable is in the catalog. This catches singletons no other pass finds.
10. **Vfunc dump** — emit one CSV row per vfunc for every vtable
11. **Hierarchy walk** — parse `ClassHierarchyDescriptor` → `BaseClassDescriptor` arrays to recover full inheritance chains

## Key implementation notes

- **TypeDescriptors are in `.data`**, not `.rdata`. The `type_info` vtable pointer at TD+0 needs to be runtime-initialized, forcing the writable section. Scanners that only check `.rdata` find zero.
- **Vtable references in x64 code are LEA RIP-relative** (`48 8D 05 disp32`), never 8-byte absolute immediates.
- **Verification-as-you-go is mandatory**. The "first store after vtable LEA" heuristic gives ~50% false positives. Reading the candidate from live memory and matching the deref'd vtable is the only reliable signal.
- **SteamStub never gets unpacked**. We work entirely against the runtime-decrypted image in process memory — same view the trainer will use.

## Build

Requires Visual Studio 2022 Build Tools, CMake 3.20+. C++17, no dependencies.

```cmd
build.cmd
```

Produces `build\Release\GHaxSkyrimDumper.exe`.

## Use

Launch Skyrim and load into a save (some singletons aren't constructed until a save is loaded — `Sky` requires an exterior cell). Then:

```cmd
build\Release\GHaxSkyrimDumper.exe
```

Outputs land in `build\Release\output\`.

## Inheritance chain verified against CommonLibSSE-NG

```
PlayerCharacter <- Character <- Actor <- TESObjectREFR <- TESForm <- BaseFormComponent
   <- BSHandleRefObject <- NiRefObject
   <- IAnimationGraphManagerHolder
   <- MagicTarget <- ActorValueOwner <- ActorState
   <- IMovementState <- IMovementInterface
```

Matches the canonical CommonLibSSE-NG headers exactly.

## File layout

```
dumper/
├── CMakeLists.txt
├── build.cmd
├── src/
│   ├── main.cpp         Orchestrator (11 phases)
│   ├── log.{h,cpp}      Tagged + timestamped logger
│   ├── process.{h,cpp}  OpenProcess + RPM helpers
│   ├── pe.{h,cpp}       PE header + section parsing
│   ├── pdata.{h,cpp}    .pdata RUNTIME_FUNCTION walker
│   ├── rtti.{h,cpp}     TypeDescriptor → COL → vtable scanner
│   ├── singletons.{h,cpp}  Constructor-anchored singleton finder
│   ├── getters.{h,cpp}     GetSingleton() accessor pattern scanner
│   ├── data_scan.{h,cpp}   Brute-force .data slot → class resolver
│   ├── vtable_dump.{h,cpp} vfunc extractor
│   └── hierarchy.{h,cpp}   ClassHierarchyDescriptor walker
└── build/Release/output/   Run output
```

## Scope

Single-player Skyrim, offline use only. The dump enables trainer development for memory-only feature implementation (god mode, ESP, free-cam, time scrub, etc.). No anti-cheat involved — Skyrim ships none, and the modding ecosystem already does far more invasive things via SKSE.
