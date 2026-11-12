# Wasm & JIT UAF Patterns

Reference for UAF patterns specific to JavaScriptCore's WebAssembly and
JIT compilation pipelines. Consult when the target code is in
`Source/JavaScriptCore/wasm/`, `Source/JavaScriptCore/yarr/`,
`Source/JavaScriptCore/dfg/`, `Source/JavaScriptCore/ftl/`,
or `Source/JavaScriptCore/b3/`.

## 1. Wasm memory backing store lifetime

When Wasm memory grows, the behavior depends on the mode:

- **Signaling mode** (default for shared memory): grows in-place by committing more
  virtual pages. Base pointer is STABLE. No UAF risk from grow.
- **BoundsChecking mode** (fallback when virtual memory is limited, or for resizable
  buffers): allocates a NEW buffer, copies data, frees old. Base pointer CHANGES.

Pointers that go stale after BoundsChecking grow:
- `ArrayBufferContents::m_data` — raw pointer to buffer base
- `JSArrayBufferView::m_vector` — cached `buffer->data() + byteOffset` in every TypedArray/DataView
- Instance cached memory base/size pairs — `JSWebAssemblyInstance::cachedMemoryBaseSizePairs`

The instance pairs are updated in `Memory::grow()`'s success lambda. The fix for
views (commit 6b357f32c607) added `refreshVector()` to update all attached views
via the ArrayBuffer's incoming-ref tracking.

**Audit anchor**: any code that calls `basePointer()`, `memory()`, or `->data()` on
a Wasm-backed buffer and holds the result across a potential `memory.grow()` or
`ArrayBuffer.resize()`.

**JIT paths are safe independently**: BBQ/OMG reload memory base from instance after
calls. IPInt/LLInt load from instance per-access.

## 2. JIT compiler graph mutation hazards (DFG)

During DFG bytecode parsing, the parser allocates `BasicBlock` objects and wires
them as branch targets. Some blocks are contingent on watchpoint state:

```
if (seenModes & FastArray && isStillValid(watchpoint)) {
    // create fastArrayBlock
    failedBlock = allocateUntargetableBlock();  // for fallthrough
}
if (seenModes & FastMap && isStillValid(watchpoint)) {
    connectFailedBlock();  // consumes failedBlock
    // create fastMapBlock
}
```

**Bug shape**: if a watchpoint is invalidated between the first and second check,
the second case is skipped. `failedBlock` was allocated but never connected — it's
an empty block (no terminal node). When `Graph::determineReachability()` walks
successors, `block->terminal()` returns nullptr → crash.

**Fix** (commit 3f4f81750dc5): filter out invalidated modes BEFORE computing
`numberOfRemainingModes`, so no contingent blocks are allocated for dead cases.

**Audit anchor**: `failedBlock`, `allocateUntargetableBlock`, `addLazily` +
`isStillValid` in `DFGByteCodeParser.cpp`. This pattern is unique to
`handleIteratorOpen` / `handleIteratorNext`.

**Exploitability**: DoS only (crash during compilation, before JIT code is emitted).
No type confusion or arbitrary R/W possible.

## 3. YARR backtracking state machine

YARR (Yet Another Regex Runtime) uses `ParenContext` objects to save/restore
backtracking state for parenthesized subexpressions. These are managed via a
custom freelist allocator.

**Lifecycle**:
1. `allocateParenContext()` — pops from freelist (or allocates new)
2. `saveParenContext()` — snapshots frame slots (including `returnAddress`) into context
3. `restoreParenContext()` — writes frame slots back from context
4. `freeParenContext()` — pushes back to freelist for reuse

**Bug shape** (commit 2d16551f697d): `restoreParenContext` restores ALL frame slots
in a global range, including sibling groups' `parenContextHead` pointers. If the
context pointed to by a restored `parenContextHead` was already freed and recycled,
the pointer is stale → UAF.

**Critical escalation**: `ParenContext` contains `returnAddress` (offset 16 on 64-bit).
`loadFromFrameAndJump()` performs `farJump()` to this address — an **indirect jump
with no CFI/PAC protection on x86_64**. Corrupted `returnAddress` in a recycled
context gives full instruction pointer control.

On ARM64E, `farJump` uses PAC-signed pointers (`YarrBacktrackPtrTag`), which adds
mitigation but doesn't fully prevent exploitation.

**Audit anchor**: `ParenContext`, `saveParenContext`, `restoreParenContext`,
`allocateParenContext`, `freeParenContext`, `loadFromFrameAndJump`, `farJump`
in `YarrJIT.cpp` / `YarrJITRegisters.h`.

**Note**: The YARR interpreter (`YarrInterpreter.cpp`) uses a different allocation
model (`ParenthesesDisjunctionContext` via pool allocator) and is NOT vulnerable
to this pattern.

## 4. IPInt / LLInt bounds checking (OOB, not UAF)

> **Note**: This section covers out-of-bounds access patterns, not UAF. It is
> included here because these bugs often co-occur with Wasm memory lifetime
> issues (Section 1) and share the same audit surface. For pure bounds-check
> analysis, see `webkit-bounds-audit`.

IPInt (Inline Processing Interpreter) and LLInt access Wasm memory via base/size
pairs loaded from the instance. Patterns to watch:

- **Memory64 pointer truncation**: IPInt slow paths may truncate 64-bit effective
  addresses to 32 bits, bypassing bounds checks. Commits afc44e3, 370255e fixed
  `memory.atomic.notify` and `memory.atomic.wait32/64` truncation.

- **Multi-memory bounds check underflow**: when memory size is 0 and the bounds
  check subtracts the access size, the result underflows → bypasses the check.
  Commit c90b978 fixed this.

- **Last-byte check omission**: bounds check validates start address but not
  `start + accessSize - 1`, allowing OOB read of the last byte(s). Commit ab77ec9.

**Audit anchor**: `boundsCheck`, `memoryBase`, `memorySize`, `effectiveAddress`
in `IPIntGenerator.cpp`, `WasmSlowPaths.cpp`, `WasmOperationsInlines.h`.

## What this file doesn't cover

- Wasm-specific semantic bugs (spec compliance) → separate skill
- Pure integer overflow in Wasm (without UAF consequence) → `webkit-int-overflow-audit`
- Type confusion in JSC bindings → `webkit-type-confusion-audit`
