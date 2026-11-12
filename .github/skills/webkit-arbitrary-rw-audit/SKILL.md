---
name: webkit-arbitrary-rw-audit
description: Deep audit playbook for ARBITRARY_RW bugs in WebKit — sites where the attacker fully controls BOTH the address AND the value of a memory write (or both the address and the size of a read). Consult when the target method casts an attacker-influenced integer to a pointer, dispatches via attacker-influenced offset/index into a vtable or function-pointer table, writes attacker-controlled bytes at an attacker-controlled offset, or implements JIT codegen with attacker-influenced operands. Returns the unchecked R/W site and the missing bound or type guard.
---

# WebKit Arbitrary R/W Audit

`ARBITRARY_RW` is the highest-impact bug class — full attacker
control of both ends of a memory operation. **Reserve this class
for actual primitives, not "could escalate to" cases.** Most
candidates downgrade to `OOB_*`, `TYPE_CONFUSION`, or `UAF`.

## 1. When this skill applies

Consult when the method:
- Casts an attacker-influenced integer to a pointer (or back)
- Indirects through an attacker-controlled offset into a function-
  pointer table or vtable
- Stores attacker-controlled bytes at an attacker-controlled offset
  into a buffer the attacker also chose
- Implements a typed-array view where both the pointer base and the
  indexing are externally reachable
- Performs JIT codegen with attacker-influenced operands or addresses
- Implements `wasm.memory.copy` / `memory.fill` with attacker dst,
  src, and len
- Maps shared memory at an attacker-supplied offset / size
- Implements a debug / inspector backdoor that forwards a raw address
- Touches JIT codegen paths (`DFG`, `FTL`, `B3`) where attacker-
  influenced values flow into code emission
- Operates on Gigacage-isolated buffers (`TypedArray` backing stores,
  Butterfly arrays) where an OOB could reach outside the cage
- Handles `StructureID` decoding, tagging, or forging where entropy
  bits could be bypassed
- Overwrites or loads PAC-signed pointers (`tagCodePtr`,
  `untagCodePtr`, vtable entries on ARM64E)
- Allocates or frees TZone-isolated objects (`MAKE_TZONE_ALLOCATED`,
  `IsoSubspace`) where cross-zone type confusion is in play

## 2. The 9-question checklist

**Answer ALL questions. Q1–Q3 determine the primitive. Q4–Q8
determine which mitigations the primitive must bypass. Q9 documents
the full chain.**

### Q1. Does the attacker control the ADDRESS?

Trace the address-computing expression to its source:
- Was the base ever set from external bytes (network, IPC, JS)?
- Was the offset added to a base ever attacker-controlled?
- Pointer-from-int casts: where did the int come from?
- Function-pointer table dispatch: who controls the index?

If the answer is no → this isn't `ARBITRARY_RW`. Try `webkit-bounds-audit`
(if there's a fixed-base, attacker-offset relationship) or
`webkit-type-confusion-audit` (if a wrong-type cast picks the address).

### Q2. Does the attacker control the VALUE (write) or SIZE (read)?

For writes:
- Are the bytes being written derived from external input?
- If only the offset is attacker-controlled but the value is fixed,
  this is `OOB_WRITE`, not `ARBITRARY_RW`.

For reads:
- Is the read length attacker-controlled?
- Does the read result reach the attacker (return to JS, IPC reply,
  any cross-origin observable)?
- A read of arbitrary memory that NEVER leaves the process is
  often `OOB_READ` of a fixed downstream sink, not `ARBITRARY_RW`.

If both ends aren't controlled, downgrade to the relevant primitive
class.

### Q3. Are there bound or type guards in between?

If the path from attacker input to the unconstrained dereference
passes through any non-trivial guard, the primitive may be
constrained:
- `Checked<>` arithmetic — bounded magnitude
- `inherits<>` / structure check — bounded type
- Cryptographic check (signature, MAC) — bounded provenance
- Sandbox boundary check (codesign, syscall filter) — bounded reach

Document which guards survive and which are bypassed in the rationale.
Severity drops if the guard constrains EITHER the address or the value
(or both).

### Q4. Does the path bypass Gigacage?

Gigacage isolates JSC auxiliary buffers (`TypedArray` backing stores,
Butterfly arrays) in a separate virtual-memory cage. An OOB within a
caged region can only reach other caged objects — NOT arbitrary process
memory.

To achieve true `ARBITRARY_RW`, the attacker must either:
- Escape the cage (read/write outside the cage region)
- Use a non-caged pointer (raw C++ heap object, stack, globals)
- Exploit a confused type that bridges caged↔uncaged memory

If the bug is entirely within Gigacage, downgrade to `OOB_WRITE` /
`OOB_READ`.

Grep: `Gigacage`, `gigacageBasePtr`, `CagedPtr`, `CagedBarrierPtr`
in JSC/WTF.

### Q5. Does the path bypass JITCage / W^X?

JITCage restricts JIT code modification to a dedicated write path
(`performJITMemcpy`). JIT memory is mapped RX (not RWX) on hardened
platforms.

To write attacker-controlled machine code, the attacker must:
- Call `performJITMemcpy` with controlled source (requires code
  signing or cage entry)
- Find a JIT spray gadget that survives JIT hardening
- Bypass W^X entirely (requires kernel-level primitive)

If JITCage is enabled, the attacker can't simply write shellcode to
JIT pages.

Grep: `performJITMemcpy`, `JITCage`, `jitWriteSeparateHeaps`,
`configureJITCage` in JSC.

### Q6. Does the path bypass StructureID entropy?

StructureIDs have entropy bits that must match during decode.
`decontaminate()` strips entropy; forging a StructureID requires
guessing the entropy bits.

- fakeobj primitive: attacker needs to set the StructureID of a fake
  object — harder with entropy
- If StructureID entropy is intact and the attacker can't leak it,
  fakeobj is probabilistic

Grep: `StructureID`, `decontaminate`, `entropyBits`,
`structureIDEntropyBits`.

### Q7. Does the path bypass PAC (Pointer Authentication)?

ARM64E signs function pointers, return addresses, and vtable entries
with PAC.

- On PAC-enabled platforms, overwriting a function pointer requires
  forging the PAC signature
- JIT code entry points are PAC-signed with `JITCodePtrTag`
- If the target platform is ARM64E and the primitive overwrites a
  function pointer, PAC blocks exploitation unless the attacker has
  a PAC signing oracle

Grep: `PtrTag`, `tagCodePtr`, `untagCodePtr`, `authenticateData`,
`arm64e`.

### Q8. Does the path bypass TZone (Type Zone) isolation?

TZone allocates each C++ type in a separate heap zone.

- A UAF that reclaims memory with a different type can only do so
  within the same zone
- Cross-zone type confusion requires a TZone bypass or finding
  same-zone conflicting types
- If TZone is enabled, assess whether the bug's replacement
  allocation is in the same zone

Grep: `TZone`, `MAKE_TZONE_ALLOCATED`, `ISO_SUBSPACE`,
`IsoSubspace`.

### Q9. What is the escalation chain?

Most `ARBITRARY_RW` is built from a chain of primitives, not a single
bug. Document the chain: e.g., "Type confusion → fakeobj → addrof →
arbitrary read → leak PAC key → arbitrary write."

- Each link in the chain may be blocked by a different mitigation
  (Gigacage, JITCage, StructureID entropy, PAC, TZone)
- If ANY link in the chain is blocked by an unbroken mitigation, the
  full `ARBITRARY_RW` is not achievable
- Downgrade to the highest primitive the chain actually reaches

## 3. CLAIM extraction

- `bug_class`: `ARBITRARY_RW` (only if Q1 AND Q2 are both yes)
- `severity`: `Critical` — this is the highest-impact class
- `unchecked_op.file:line` — the deref / store / indirect-call line
- `missing_check.file:line` — where the bound or type guard should go
- `primitive` — describe the precise primitive: "attacker writes
  arbitrary 8 bytes at arbitrary 64-bit address from JS via
  `WebAssembly.Memory.grow` after type-confusion at line X"
- `patch_counterfactual` — usually a chain: bound the address +
  bound the size + restrict the type. Single-line patches rarely
  close `ARBITRARY_RW` bugs cleanly.

## 4. Reference materials

Read these from the same directory if you need depth:

- `arw-mitigation-catalog.md` — the 5 mitigation surfaces (TZone,
  PAC, JITCage, StructureID, Gigacage) with purpose, mechanism,
  coverage, known limitations, audit implications, and exemplar
  commits from 313 hardening commits over 5 years.
- `mitigation-landscape.md` — all 9 WebKit exploit mitigations
  (Gigacage, JITCage, StructureID, PAC, TZone, MTE, CFI, Sandbox,
  ProcessSwap) with detailed mechanism descriptions and key files.
- `escalation-chains.md` — 5 canonical escalation chains from
  primitive bugs to ARBITRARY_RW, with per-step mitigation mapping
  and a quick-reference matrix.

## 5. WebKit-specific anchors (rare, high-value)

- JSC JIT codegen with attacker-influenced operands
  (`Source/JavaScriptCore/jit/`, `Source/JavaScriptCore/dfg/`,
  `Source/JavaScriptCore/ftl/`, `Source/JavaScriptCore/b3/`)
- `WebAssembly.Memory.grow` / `memory.copy` / `memory.fill` with
  attacker-controlled count
- JSC `TypedArray` with attacker-controlled `byteOffset` and `length`
  through a confused buffer
- Plugin bridge / NPAPI legacy paths
- IPC shared memory mapping with attacker-supplied offset and size
- Canvas WebGL `bufferData` / `bufferSubData` / `texImage*` with
  attacker-controlled target / usage / data when the underlying
  GL state was attacker-influenced
- Inspector / RemoteDebugger paths that take raw addresses
  (audit only when these are reachable from sandboxed renderer)

## 6. Most ARBITRARY_RW claims are downgrades

If you find yourself about to claim `ARBITRARY_RW`, double-check:

> "Could an attacker actually pick BOTH (address, value) — not just
>  one, with the other determined by the bug's structure?"

If not, the right class is one of:
- `OOB_WRITE` — attacker picks offset, value is fixed/limited
- `HEAP_OVERFLOW` — linear write past chunk boundary
- `TYPE_CONFUSION` — write through wrong-type lens (limited range)
- `UAF` — write through dangling pointer at attacker-influenced
  address (range bounded by what gets allocated there next)

`ARBITRARY_RW` is for the rare "attacker has full `*addr = value`
primitive" case. If you can't articulate the EXACT
`(controlled_address, controlled_value, observable_effect)` triple,
file the upstream class instead.

## 7. What this skill won't help with

- Anything that's "could escalate to" `ARBITRARY_RW` — use the actual
  primitive's skill (`webkit-uaf-audit`, `webkit-type-confusion-audit`,
  `webkit-bounds-audit`).
- Pure info-leak primitives that don't write → `webkit-uninit-read-audit`
  or `webkit-bounds-audit` for OOB_READ.
