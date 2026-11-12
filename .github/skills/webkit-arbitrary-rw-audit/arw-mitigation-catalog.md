# WebKit Arbitrary R/W — Mitigation-Surface Catalog

> **Note**: This is **not** a bug-pattern catalog. Arbitrary read/write is rarely a
> single bug — it is an escalation goal assembled from chains of primitive
> vulnerabilities (type confusion, OOB access, UAF, integer overflow). Rather
> than cataloging individual bug shapes, this document maps the **mitigation
> surface** that an attacker must defeat to turn a primitive bug into a useful
> arbitrary R/W primitive, and the **escalation paths** each mitigation blocks.
>
> **Methodology**: Bottom-up analysis of 313 hardening / mitigation commits
> across WebKit (2021-01-01 → 2026-05-31). Each commit was classified by the
> mitigation surface it strengthens, its coverage scope, and known
> limitations. The result is a taxonomy of **5 major mitigation surfaces**
> that collectively define the difficulty of achieving arbitrary R/W in modern
> WebKit.

---

## Mitigation investment summary

| ID | Mitigation Surface | 5yr Commits | Status |
|----|-------------------|:-----------:|--------|
| ARW-TZONE | Type Zone / heap isolation | 90 | Active deployment (2023–2026) |
| ARW-PAC | Pointer authentication | 27 | Mature (ARM64E only) |
| ARW-JITMEM | JIT memory protection (W^X / JITCage) | 14 | Mature |
| ARW-STRUCTID | StructureID entropy | 3 | Mature (reduced to 5 bits) |
| ARW-GIGACAGE | Gigacage buffer isolation | 1 | Mature (stable) |

---

## Mitigation-surface entries

---

### ARW-TZONE: Type Zone / Heap Isolation
**Purpose**: Blocks type-confusion and UAF→object-overlap escalation by
ensuring that objects of different C++ types are never allocated from the same
heap bucket, so freeing object A cannot yield a same-sized allocation of
object B in the same virtual address.

**Mechanism**: TZone extends bmalloc with per-type heap zones. Each C++ class
opted into TZone receives its own segregated free-list (or a shared bucket
keyed by type identity). `FastMalloc`-allocated classes are progressively
migrated to `TZoneMalloc` via `WTF_MAKE_TZONE_ALLOCATED`.

**Coverage**: Covers DOM nodes, RenderObject subtypes, JSC cells, and most
security-sensitive WebCore/WebKit objects that have been converted. Objects
that still use raw `FastMalloc` or system `malloc` are **not** protected — they
remain in general-purpose buckets where type-confused reuse is possible.

**Known limitations**:
- Migration is incremental; unconverted classes remain unprotected.
- When MTE (Memory Tagging Extension) is enabled, TZone allocations are
  disabled in favor of MTE's probabilistic tagging (`174feea3cd59`).
- Objects in the same TZone bucket (same declared type) can still be
  confused with each other — TZone only isolates across *different* types.
- Per-process bucket count is configurable (`101108025a14`); a low count
  increases collision probability.

**5yr commit activity**: 90 commits — bulk conversion of FastMalloc classes
to TZone across WebCore, WebKit, JavaScriptCore, and WTF. Includes
infrastructure (TZoneHeapManager, TZoneLog), per-process bucket policy API,
and MTE interop.

**Key files**:
- `Source/bmalloc/bmalloc/TZoneHeap.h` / `.cpp`
- `Source/bmalloc/bmalloc/TZoneHeapManager.h` / `.cpp`
- `Source/bmalloc/bmalloc/TZoneLog.h` / `.cpp`
- `Source/bmalloc/bmalloc/TZoneHeapInlines.h`
- `Source/WTF/wtf/TZoneMalloc.h` (macro definitions)

**Audit implications**: When auditing object lifetime bugs (UAF, type
confusion), check whether the relevant types use `WTF_MAKE_TZONE_ALLOCATED`.
If they share a bucket or use plain `FastMalloc`, a UAF on one type may yield
an attacker-controlled object of another type in the same allocation slot.

**Exemplar commits**:
- `017d642ad8ad` — WebKit misc: Convert FastMalloc to TZone for assorted classes
- `101108025a14` — Add API for processes to set their own TZone bucket count policy
- `174feea3cd59` — Disable TZone allocations when MTE is enabled

---

### ARW-PAC: Pointer Authentication (ARM64E)
**Purpose**: Blocks control-flow hijacking after an arbitrary write by
cryptographically signing code pointers (return addresses, function pointers,
vtable entries, ObjC method caches) so that corrupted values fail
authentication before use.

**Mechanism**: ARM64E `ptrauth` instructions sign pointers with a key and a
context discriminator (often the storage address or a type hash). WebKit uses
`PtrTag` to classify pointer kinds and applies `tagCFunction` /
`untagCFunction` at signing/verification boundaries. JIT-emitted code
authenticates entry points; vtable pointers use
`WTF_VTBL_FUNCPTR_PTRAUTH_STR`.

**Coverage**: Return addresses, JIT entry thunks, ObjC dispatch, JSC opcode
dispatch tables, DOMJIT signature function pointers. Applies only on ARM64E
hardware (Apple Silicon); all other architectures have **no** PAC protection.

**Known limitations**:
- x86_64 and non-Apple ARM64 builds have zero coverage.
- Signing uses a limited key space (A/B keys, instruction/data); context
  diversity depends on correct discriminator choice.
- Data-only attacks (corrupting non-pointer fields to influence control flow
  indirectly) are not mitigated by PAC.
- A signing oracle (ability to call `ptrauth_sign` with chosen data) can
  forge valid pointers.

**5yr commit activity**: 27 commits — hardening of interpreter dispatch
tables, DOMJIT unsafe-function-pointer diversity, Mach exception handler
signing, BoringSSL PAC enablement, and BlockPtr ptrauth fixes.

**Key files**:
- `Source/WTF/wtf/PtrTag.h` / `.cpp`
- `Source/JavaScriptCore/runtime/JSCPtrTag.h` / `.cpp`
- `Source/JavaScriptCore/jit/ThunkGenerators.cpp`
- `Source/JavaScriptCore/llint/LowLevelInterpreter.asm`

**Audit implications**: When auditing function-pointer tables, JIT entry
points, or ObjC dispatch sites, verify that all code pointers are signed with
an appropriate `PtrTag` and authenticated before use. Check that
discriminator diversity is sufficient (address-diversified, not just
key-diversified). Look for unsigned function pointers that could serve as
signing oracles or bypass targets.

**Exemplar commits**:
- `d5e7d2a3eeee` — Harden interpreter dispatchers more for ARM64E
- `f8257caba2e1` — Harden diversity of DOMJIT::Signature::unsafeFunction pointer
- `9155990f3566` — Hardened Mach exception signing key can't be zero
- `d13215b96086` — Enable PAC (return address signing) in BoringSSL

---

### ARW-JITMEM: JIT Memory Protection (W^X / JITCage)
**Purpose**: Blocks shellcode injection and JIT-spray attacks by ensuring
that JIT-compiled code memory is never simultaneously writable and executable
(W^X), and by confining JIT code execution to a dedicated cage region.

**Mechanism**: JIT pages are mapped RX during execution and temporarily
switched to RW (or written via a separate mapping) only during code emission.
`performJITMemcpy` (and its atomic variant `performJITMemcpyAtomic`)
copy generated code into executable pages through a controlled write
primitive. JITCage further restricts execution to a pre-allocated memory
region; indirect calls into JIT code must target addresses within the cage.

**Coverage**: All JIT tiers (Baseline, DFG, FTL), Wasm compiled code, CSS
JIT, and YARR JIT. JITCage is supported on Apple platforms with hardware
support; it is disabled under ASAN (`299f0aa7d776`).

**Known limitations**:
- JITCage is disabled on non-Apple platforms and under sanitizers.
- The `performJITMemcpy` window (RW mapping) is a race-condition surface if
  not properly serialized.
- JIT gadget reuse (chaining existing JIT-emitted instruction sequences) is
  not blocked by W^X or JITCage — only new code injection is prevented.
- Wasm String builtins required explicit JITCage enablement (`12421d94ba14`),
  suggesting new JIT paths may miss cage registration.

**5yr commit activity**: 14 commits — JITCage runtime flag, atomic JIT
memcpy, Wasm String builtin cage enablement, ASAN/MacCatalyst configuration
fixes.

**Key files**:
- `Source/JavaScriptCore/jit/ExecutableAllocator.h` / `.cpp`
- `Source/JavaScriptCore/jit/JITStubRoutine.h` / `.cpp`
- `Source/JavaScriptCore/assembler/LinkBuffer.cpp`
- `Source/JavaScriptCore/assembler/AssemblerBuffer.h`
- `Source/JavaScriptCore/runtime/JSCConfig.h` (JITCage flag)

**Audit implications**: When auditing JIT code emission paths, verify that
all writes go through `performJITMemcpy` or `performJITMemcpyAtomic` — never
direct memory writes to executable pages. For new JIT tiers or builtins,
confirm JITCage registration. Check that the RW window is minimized and
properly guarded.

**Exemplar commits**:
- `06b3353a1bb8` — Add runtime flag to allow JITCage experiments
- `06f449154f24` — Add performJITMemcpyAtomic and simplify JIT copying code
- `12421d94ba14` — Enable JITCage support in Wasm JS String builtins
- `299f0aa7d776` — Disable JITCage by default when ASAN is enabled

---

### ARW-STRUCTID: StructureID Entropy
**Purpose**: Blocks Structure-pointer forgery in JSC by encoding StructureID
values with random entropy bits, so that an attacker who can write an
arbitrary 32-bit value into a JSCell header cannot predict a valid
StructureID for a target Structure.

**Mechanism**: StructureID values are XOR'd with a per-process random nonce
during encoding. The `decode()` path calls `decontaminate()` to strip the
entropy and recover the actual Structure table index. The entropy occupies
the high bits of the 32-bit StructureID.

**Coverage**: All JSC heap objects (JSCell subclasses) that carry a
StructureID in their header. This is the primary defense against
type-confusion attacks that corrupt JSCell headers.

**Known limitations**:
- Entropy was reduced from 7 bits to 5 bits (`88c631c44059`) to make room
  for more StructureIDs — this means only 32 possible nonce values, making
  brute-force feasible in ~16 attempts on average.
- If an attacker can leak the entropy nonce (via an info leak), the
  mitigation is fully bypassed.
- `decontaminate()` must be called in every decode path; a missed call
  allows use of a contaminated (still-XOR'd) StructureID, which may alias
  a different Structure.

**5yr commit activity**: 3 commits — `decontaminate()` enforcement in decode
paths, entropy-bit reduction from 7 to 5.

**Key files**:
- `Source/JavaScriptCore/runtime/StructureID.h`
- `Source/JavaScriptCore/runtime/StructureIDTable.h`
- `Source/JavaScriptCore/runtime/StructureIDTable.cpp`

**Audit implications**: When auditing StructureID handling, verify that
`decontaminate()` is called on every path that decodes a raw StructureID
value. Be aware that with only 5 entropy bits, an attacker with a
corruption primitive and the ability to retry (e.g., via a web worker
respawn) can brute-force a valid StructureID. Check whether info-leak paths
could expose the entropy nonce.

**Exemplar commits**:
- `02b0bfc51d45` — Use decontaminate() in StructureID::decode
- `88c631c44059` — Reduce StructureID entropy bits to 5 to make room for more IDs

---

### ARW-GIGACAGE: Gigacage Buffer Isolation
**Purpose**: Blocks out-of-bounds access on JSC-managed buffers (Butterfly
arrays, typed arrays, strings) from reaching arbitrary memory by confining
all such buffers to a large pre-reserved virtual address region (the
"Gigacage"). OOB within the cage cannot escape to read/write heap metadata,
stack, or code pages.

**Mechanism**: At process startup, bmalloc reserves a multi-gigabyte virtual
address region for each cage kind (Primitive, JSValue). All JSC buffer
allocations (Butterfly backing stores, TypedArray backing stores, string
storage) are placed within this region. Pointer arithmetic that stays within
the cage bounds cannot reach outside it; base pointers are masked on access
to enforce confinement.

**Coverage**: JSC Butterfly arrays, TypedArray backing stores, and string
storage. Does **not** cover arbitrary C++ heap allocations, DOM node storage,
or non-JSC buffers.

**Known limitations**:
- Only JSC-managed buffers are caged; C++ heap objects, render tree nodes,
  and platform allocations are outside the cage.
- Gigacage can be disabled by entitlement or environment variable for
  debugging, which removes all protection.
- If an attacker achieves an arbitrary write *inside* the cage, they can
  corrupt adjacent JSC buffers (Butterfly→TypedArray confusion) to build
  further primitives.
- 32-bit processes may not have sufficient address space for full Gigacage.

**5yr commit activity**: 1 commit — entitlement update for CaptivePortal to
support full Gigacage. The infrastructure is mature and stable; no
architectural changes in the 5-year window.

**Key files**:
- `Source/bmalloc/bmalloc/Gigacage.h` / `.cpp`
- `Source/bmalloc/bmalloc/GigacageConfig.h`
- `Source/bmalloc/bmalloc/GigacageKind.h`
- `Source/JavaScriptCore/heap/GigacageAlignedMemoryAllocator.h` / `.cpp`
- `Source/JavaScriptCore/runtime/ArrayBuffer.cpp`

**Audit implications**: When auditing TypedArray, Butterfly, or string buffer
access paths, verify that base pointers are caged (masked to the Gigacage
region). Check for code paths that operate on raw uncaged pointers extracted
from JSC objects — these bypass Gigacage. Ensure that Gigacage is not
disabled via entitlement in production builds.

**Exemplar commits**:
- `1d854253121c` — Update CaptivePortal entitlements to support full Gigacage

---

## What to look for when auditing

### When auditing JSC JIT code
- Verify all code emission goes through `performJITMemcpy` / `performJITMemcpyAtomic`.
- Confirm new JIT paths register with JITCage (not just W^X).
- Check that JIT entry-point addresses are PAC-signed before storage and
  authenticated before indirect call.
- Look for JIT gadget chains that survive W^X but could be reused.

### When auditing C++ object lifetimes
- Check whether the type uses `WTF_MAKE_TZONE_ALLOCATED`; if not, a UAF can
  yield same-sized objects of different types in the same bucket.
- Identify "same-zone type conflicts" — two different classes that share a
  TZone bucket and have exploitably different layouts.
- Cross-reference with the UAF pattern catalog for the primitive bug shapes
  that feed into TZone bypass.

### When auditing TypedArray / Butterfly access
- Verify that buffer base pointers are Gigacage-confined (masked on load).
- Check for paths that extract raw pointers and pass them outside JSC
  (e.g., into WebGL, WebAudio, or Wasm memory) without re-caging.
- Look for index arithmetic that could wrap or alias within the cage to hit
  adjacent buffers.

### When auditing StructureID usage
- Verify that `decontaminate()` is called in every StructureID decode path.
- Assess whether a brute-force attack (5-bit entropy = ~16 average attempts)
  is feasible given the bug's retry characteristics.
- Check for info-leak paths that could expose the per-process entropy nonce.

### When auditing function-pointer tables
- Verify all function pointers are PAC-signed with appropriate `PtrTag`.
- Check discriminator diversity — address-diversified is stronger than
  key-only diversified.
- Look for data-only attack paths that influence control flow without
  corrupting a signed pointer (e.g., corrupting a vtable index rather than
  the vtable pointer itself).

---

## Adding new entries

When a new mitigation surface is introduced or significantly modified in
WebKit:

1. **Assign an ID**: `ARW-XXXX` (short mnemonic).
2. **Fill in the template**:
   - Purpose, Mechanism, Coverage, Known limitations
   - 5yr commit activity, Key files, Audit implications
   - At least 2 exemplar commits with hashes and descriptions
3. **Update the summary table** at the top.
4. **Cross-reference** with the UAF pattern catalog and type-confusion
   catalog if the mitigation surface affects those bug classes.
5. **Submit a PR** with the catalog update and any corresponding changes to
   the `SKILL.md` system prompt.
