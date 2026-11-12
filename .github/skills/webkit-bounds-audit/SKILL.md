---
name: webkit-bounds-audit
description: Deep audit playbook for out-of-bounds read/write bugs in WebKit covering HEAP_OVERFLOW, STACK_OVERFLOW, OOB_WRITE, OOB_READ, and RACE_TO_OOB. 12-question checklist spanning generic bounds patterns (Q1-Q5) and WebKit-subsystem-specific patterns including Wasm memory, typed arrays, image/media codecs, GPU/WebGL/WebGPU, stack overflow, integer overflow, and YARR regex (Q6-Q12). Consult when the target method indexes a buffer, calls memcpy/memmove/memset, constructs a span/StringView/ArrayBufferView/SharedBuffer view with a computed length, calls Vector::reserveCapacity/resize, holds a Vector::data() pointer across mutations, handles Wasm memory operations, computes image/media buffer sizes, accesses GPU texture/buffer data, recurses on external input, or handles YARR input positions. Returns the unchecked op site, the missing bound, and a minimal patch.
---

# WebKit Bounds Audit

Catches classic out-of-bounds bugs at any sink: heap (HEAP_OVERFLOW),
stack (STACK_OVERFLOW), or other (OOB_WRITE/READ). The procedure is the
same for all four — only the severity bucket differs based on the sink's
allocator.

## 1. When this skill applies

Consult when the method:
- Calls `memcpy` / `memmove` / `memset` / `bcopy` / `strcpy` / `strncpy` /
  `snprintf` / `vsnprintf` / `std::copy` / `std::fill`
- Indexes a container: `vec[i]`, `vec.at(i)`, `span[i]`, `data()[offset]`,
  `string.characters8()[i]`
- Constructs a view from `(ptr, length)`: `std::span`, `WTF::Span`,
  `StringView`, `ArrayBufferView`, `unsafeMakeSpan`
- Calls `Vector::reserveCapacity`, `Vector::resize`, `Vector::grow`,
  `Vector::shrink`, `Vector::append` (when followed by data() use)
- Reads from a `SharedBuffer` segment by offset
- Writes to a graphics buffer / `IOSurface` / GPU texture by row+column
- Computes `byteOffset + length` against an `ArrayBuffer` size
- The method is in `Source/JavaScriptCore/wasm/` or handles Wasm memory operations
- The method is in an image/media decoder and computes buffer sizes from dimensions
- The method is in WebGL/WebGPU/GPU process and accesses texture/buffer data
- The method recurses on external input (JSON parse, DOM tree walk, CSS rule eval)
- The method is in YARR and handles input position or backref indices

## 2. The 12-question checklist

Answer ALL questions that match the triggers in Section 1.

### Q1. What's the bound, and where is it set?

For every `[]`, `at()`, `data() + N`, span/view construction, sized I/O:
- What's the maximum legal index/length/offset for THIS specific buffer?
- Where is that bound captured? (constructor arg, `reserveCapacity`,
  `resize`, allocation size, IDL-validated input, …)
- Is the source attacker-controlled?

If you can't answer all three in 60 seconds of grep, the bound is
likely not enforced — proceed to Q2 with that hypothesis.

> **Cross-ref:** For Wasm memory bounds → Q6. For typed array / Butterfly
> bounds → Q7. For image/media buffer sizes → Q8. For GPU buffer bounds → Q9.

### Q2. Is there a check on the SAME control-flow path?

Bounds checks count only if EVERY path from check to use guarantees
the bound holds. Common bypasses:
- Check on one branch but use on another (early-return paths skip it)
- Check-then-grow-then-use (`Vector::data()` invalidates on grow!)
- Check captures a stale value while another thread mutates the bound
  (RACE_TO_OOB candidate — see Q5)
- Check is `ASSERT(...)` (debug-only) — release builds skip it; for
  attacker-reachable code, only `RELEASE_ASSERT` counts

> **Cross-ref:** For Wasm bounds checks that miss access size → Q6.
> For DFG/FTL JIT checks that diverge from interpreter → Q7.
> For stack depth checks that use debug-only ASSERT → Q10.

### Q3. Is the index/length type wide enough?

```cpp
// ❌ multiplication in 32-bit even though destination is size_t
size_t size = width * height * bytesPerPixel;

// ❌ negative int sign-extends to huge unsigned
size_t size = static_cast<size_t>(possibly_negative_int);

// ❌ truncation drops high bits
uint32_t lo = some_size_t;
```

If the bug is fundamentally arithmetic and the OOB sink isn't reached
in this method, prefer `webkit-int-overflow-audit` instead.

> **Cross-ref:** For image `width × height × bytesPerPixel` overflow → Q8.
> For 32-bit multiplication / truncation patterns → Q11.

### Q4. Pick the right sink class for severity

| Sink lives on | Class | Severity prior |
|---|---|---|
| Stack frame (local array, fixed-size struct field, alloca) | `STACK_OVERFLOW` | High (ROP/COP, canary bypass) |
| Heap (FastMalloc, IsoMalloc, malloc, new T[n]) | `HEAP_OVERFLOW` | High |
| JS heap (Butterfly, ArrayStorage, JSC cells) | `OOB_WRITE` | Critical (JIT-reachable) |
| GPU / IOSurface / SharedMemory | `OOB_WRITE` | High (cross-process) |
| Reading attacker-controlled buffer (no write) | `OOB_READ` | Medium (info-leak) |
| Per-thread bound check that races | `RACE_TO_OOB` | depends on win window |

> **Cross-ref:** Q4 classifies the sink. For subsystem-specific sink
> patterns, also check Q6 (Wasm), Q7 (JS heap), Q8 (image/media),
> Q9 (GPU).

Per the taxonomy precedence: name the sink, not the upstream cause.
If integer overflow drives the heap write, the class is `HEAP_OVERFLOW`
(use `INT_OVERFLOW_TO_OOB` only when the sink isn't reached in scope).

### Q5. Race-to-OOB

If a separate thread can change the buffer size between bound check
and use:
```cpp
if (m_buffer.size() > offset + length) {  // check
    // <-- another thread shrinks m_buffer here
    memcpy(dst, m_buffer.data() + offset, length);  // use → OOB
}
```
Class: `RACE_TO_OOB`. Common between main and compositor / GPU thread,
or between IPC dispatch and reply.

### Q6. Wasm memory bounds check bypass? (19 bugs in 5yr)

- **IPInt/LLInt/OMG/BBQ tiers:** does the bounds check cover the full
  access size (`start + accessSize - 1 < memorySize`), not just `start`?
- **Memory64:** is the effective address truncated from 64-bit to 32-bit
  before the bounds check? (silently wraps huge addresses into range)
- **Multi-memory:** does the bounds check use the correct memory index?
  A `memory.load` from memory 1 checked against memory 0's size is OOB.
- **`memory.copy` / `memory.fill`:** are `src + len` and `dst + len`
  BOTH validated against the respective memory size?

Grep: `boundsCheck`, `effectiveAddress`, `memoryBase`, `memorySize`
in `Source/JavaScriptCore/wasm/`.

### Q7. JS typed array / Butterfly OOB? (22 bugs in 5yr)

- **TypedArray `set()`:** does it validate `objectOffset + length`
  doesn't overflow `uint32`? Overflow wraps to small value → OOB write.
- **Butterfly access:** is the index checked against `publicLength`,
  NOT `vectorLength`? `vectorLength` includes pre-allocated capacity
  that may hold stale or out-of-bounds data.
- **DataView:** is `byteOffset + elementSize` checked against
  `byteLength`? Off-by-one when `elementSize > 1`.
- **DFG/FTL JIT:** does the JIT-compiled bounds check match the
  interpreter's semantics exactly? Mismatches are exploitable.

Grep: `publicLength`, `vectorLength`, `Butterfly`,
`typedArrayByteOffset`.

### Q8. Image/media codec size overflow? (10 bugs in 5yr)

- **`width × height × bytesPerPixel`:** is this computed with
  `Checked<size_t>`? Plain multiplication overflows silently in 32-bit.
- **ICC profile:** is `tagOffset + tagSize ≤ profileSize` verified
  without overflow? Both are `uint32_t` — the addition wraps.
- **Video frame:** is `stride × height` checked before NV12/I420
  buffer allocation? Mismatch between expected and actual plane sizes
  yields heap OOB.

Grep: `Checked<size_t>`, `width * height`, `bytesPerPixel`,
`storageSize`.

### Q9. GPU/WebGL/WebGPU buffer overflow? (11 bugs in 5yr)

- **WebGL `drawArrays` / `drawElements`:** is `vertexCount × stride`
  checked against the buffer's byte length?
- **WebGPU buffer copy:** is `srcOffset + size ≤ buffer.size`
  validated, including for mapped ranges?
- **WebGPU render pass:** is the attachment index within bounds of
  the render pass descriptor's attachment list?
- **IOSurface / SharedMemory:** does the mapped size match the
  expected plane sizes? Cross-process mismatch = OOB.

Grep: `drawArrays`, `drawElements`, `copyBufferToBuffer`,
`getMappedRange`.

### Q10. Stack overflow / recursion exhaustion? (27 bugs in 5yr)

- Does the function recurse on attacker-controlled input (JSON parse,
  DOM tree walk, CSS selector/rule evaluation)?
- Is there a stack depth limit check BEFORE the recursive call?
- Is the stack check `RELEASE_ASSERT` or just `ASSERT`? Debug-only
  assertions don't protect release builds against deep recursion.

Grep: `StackCheck`, `hasStaticRecursionLimit`, `maxDepth`,
`stackLimit`.

### Q11. Integer overflow / truncation to OOB? (12 bugs in 5yr)

- Is a size or offset computed by multiplying attacker-controlled
  values in 32-bit arithmetic? (wrap → small alloc → heap OOB)
- Is a `size_t` truncated to `uint32_t` before use as an allocation
  size or index? High bits are silently dropped.
- Is a signed `int` used as a size that could be negative? Negative
  sign-extends to a huge `unsigned` → massive memcpy / alloc.

Grep: `Checked<`, `checkedProduct`, `static_cast<uint32_t>`,
`toUInt32`.

### Q12. Regex engine (YARR) bounds? (8 bugs in 5yr)

- **YARR JIT:** is the input position checked against input length
  AFTER `baseOffset` adjustment? Off-by-`baseOffset` reads past end.
- **Backreference index:** is the named/numbered backref index
  validated against the capture group count?
- **SIMD → scalar fallback:** does the scalar loop check bounds after
  the SIMD fast path exits mid-vector? Remaining elements can overrun.

Grep: `inputPosition`, `baseOffset`, `m_backrefCount`,
`SIMD.*scalar` in `Source/JavaScriptCore/yarr/`.

## 3. CLAIM extraction

- `unchecked_op.file:line` — the SINK (memcpy line, [] line, span ctor)
- `missing_check.file:line` — where the bound assertion should be inserted
- `bug_class` — by sink allocator (Q4 table)
- `patch_counterfactual` — typically `RELEASE_ASSERT(x < bound)`,
  a `Checked<size_t>` conversion with overflow check, or replacing the
  raw access with a bounded variant (`span.first(n)`, `Vector::at(i)`)

## 4. Reference materials

Read these from the same directory if you need depth:

- `bounds-pattern-catalog.md` — the 17-pattern taxonomy derived from
  5 years (684 commits, 250 classified) of WebKit bounds-bug history.
  Each pattern has shape, trigger, sink, escalation, frequency, grep
  anchors, canonical code, and exemplar commits. Start here to
  understand which patterns are most frequent in the target's subsystem.
- `size-arithmetic-cheatsheet.md` — safe vs unsafe size/length/offset
  arithmetic, `Checked<T>` primitives, JSC value→size conversions,
  StringImpl length limits.
- `image-codec-bounds.md` — image decoder OOB patterns, per-decoder
  audit anchors, video frame size formulas, WebGL texture uploads,
  ICC profile overflow.
- `wasm-bounds-patterns.md` — Wasm memory access tiers, 5 common OOB
  bug shapes (last-byte omission, Memory64 truncation, multi-memory
  confusion, 0-size underflow, copy/fill length), audit anchors.

## 5. What this skill won't help with

- Pure integer-arithmetic bugs that DON'T reach a sink in the same
  method → `webkit-int-overflow-audit`.
- Lifetime / dangling-pointer bugs at the sink → `webkit-uaf-audit`.
- Type-tag confusion that drives an OOB → start with
  `webkit-type-confusion-audit`; this skill if a confirmed bound is
  bypassed by the wrong type assumption.

## Oracle citations (mandatory for high-risk bug classes)

You may have access to `oracle_method_facts(method)`. **Call it before
concluding CLEAN.** The FactSheet shows:

  - `idl_exposure.exposed_to_worker` — does this method run on a Worker?
  - `mutable_globals_touched[]`        — what `static`/`NeverDestroyed`
                                         singletons does this method touch?
  - `callers_1hop[]`                   — 1-hop reverse call graph
  - `thread_protections.*`             — main-thread asserts, lock holdings,
                                         transitively over callers

Required citations on a CLEAN, when this skill matches:

| Bug class                                | Required citations |
|------------------------------------------|--------------------|
| RACE_TO_UAF / RACE_TO_OOB / RACE_TO_TC    | both `idl_exposure.exposed_to_worker` AND `mutable_globals_touched` |
| UAF                                       | one of `callers_1hop`, `thread_protections.self_asserts_main_thread`, `thread_protections.callers_asserting_main_thread` |
| (other classes today)                     | best-effort; not yet enforced |

Schema: `factsheet_citations: [{field_path, value, what_it_proves}, ...]`.
Missing citations on a high-risk-hint clean cause it to be marked
`unverified_citation` and forced through a cross-vendor clean-check
even when both vendors agreed CLEAN. This reduces the risk of a shared,
unsupported assumption being accepted without further review.
