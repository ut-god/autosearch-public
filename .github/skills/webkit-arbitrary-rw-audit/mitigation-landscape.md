# WebKit Exploit Mitigation Landscape

Reference for auditors assessing whether a primitive bug can escalate
to ARBITRARY_RW. Each mitigation blocks a specific escalation step.

## Mitigation table

| Mitigation | What it protects | Escalation step blocked | Bypass difficulty |
|---|---|---|:---:|
| Gigacage | JSC auxiliary buffers (TypedArray, Butterfly, strings) | OOB within cage → arbitrary process memory | High (requires cage escape) |
| JITCage / W^X | JIT code pages | Write shellcode to executable memory | Very High (requires kernel primitive) |
| StructureID entropy | JSCell Structure pointer | fakeobj with forged StructureID | Medium (entropy is 5–7 bits) |
| PAC (ARM64E) | Function pointers, return addresses, vtables | Overwrite function pointer → code exec | High (requires PAC oracle) |
| TZone / IsoHeap | C++ object allocation by type | UAF reclaim with different-type object | Medium (same-zone types may exist) |
| MTE (Memory Tagging) | Heap memory tags | UAF/OOB via tagged pointer mismatch | Medium-High (probabilistic on tag) |
| CFI (Control Flow) | Indirect call targets | Hijack vtable / function pointer dispatch | High |
| Sandbox | Process capabilities | Renderer → kernel / file system | Very High |
| ProcessSwap | Cross-origin isolation | Renderer compromise → cross-site data | High |

## Gigacage details

- Auxiliary buffers (ArrayBuffer backing, Butterfly auxiliary,
  JSString chars) are allocated in a contiguous virtual memory region
- `CagedPtr<T>` wraps pointers to enforce cage membership on deref
- `CagedBarrierPtr<T>` adds write-barrier for GC
- Cage base + size set at process start; OOB within cage can reach
  any caged allocation but NOT stack/heap/globals outside the cage
- Key files: `Source/bmalloc/bmalloc/Gigacage.h`,
  `Source/WTF/wtf/CagedPtr.h`

## JITCage / W^X details

- JIT code is allocated via `FixedVMPoolExecutableAllocator` in a
  separate virtual region
- `performJITMemcpy()` is the ONLY path to write into JIT pages
  (enforced by page permissions)
- On hardened platforms (iOS), JIT region is RX; writing requires a
  syscall-level permission toggle
- JITCage further restricts JIT entry to authenticated call sites
- Key files: `Source/JavaScriptCore/jit/ExecutableAllocator.h`,
  `Source/JavaScriptCore/assembler/JITOperationList.h`

## StructureID entropy details

- StructureID is a compressed pointer to Structure with 5 entropy bits
- Decode: StructureID XOR entropy → `Structure*`
- Attacker forging a fakeobj must guess entropy bits (1/32 probability
  on 5 bits)
- `decontaminate()` strips entropy for safe comparison
- Key files: `Source/JavaScriptCore/runtime/StructureID.h`

## PAC details

- ARM64E hardware feature: pointer authentication codes
- JSC signs: JIT code entry (`JITCodePtrTag`), C function pointers
  (`CFunctionPtrTag`), return addresses
- Forging requires: known key + context, or a signing oracle (call to
  `tagCodePtr` with attacker-controlled data)
- Key files: `Source/WTF/wtf/PtrTag.h`,
  `Source/JavaScriptCore/jit/JITCode.h`

## TZone / IsoHeap details

- `MAKE_TZONE_ALLOCATED` macro: allocates each class in its own
  bmalloc heap zone
- `ISO_SUBSPACE`: allocates JSCell subclasses in type-specific GC
  subspaces
- Prevents cross-type UAF exploitation (freed Foo can only be
  replaced by another Foo)
- Key files: `Source/bmalloc/bmalloc/TZoneHeap.h`,
  `Source/JavaScriptCore/heap/IsoSubspace.h`,
  `Source/JavaScriptCore/heap/IsoSubspacePerVM.h`

## When in doubt

If you cannot determine which mitigations apply to a given primitive
within 60 seconds, flag the primitive as needing full chain analysis.
Bugs whose escalation path is unclear have historically been
underrated and later exploited.
