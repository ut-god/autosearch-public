---
name: webkit-int-overflow-audit
description: Deep audit playbook for INT_OVERFLOW_TO_OOB bugs in WebKit. Consult when the target method performs integer arithmetic on attacker-influenced operands prior to allocation, indexing, or sized I/O. Covers overflow, underflow, signedness flips, truncation, and shift bugs. Returns the arithmetic primitive site, the missing Checked<> guard, and a minimal patch.
---

# WebKit Integer Overflow Audit

`INT_OVERFLOW_TO_OOB` is a *primitive* bug class — the arithmetic itself
is the bug, even if the OOB sink is in a different method or never
reached at all in scope. If the OOB sink IS reached in this method,
prefer the sink class (consult `webkit-bounds-audit`).

## 1. When this skill applies

Consult when the method:
- Multiplies two or more attacker-influenced integers
- Adds offsets to lengths (`offset + length`, `base + size`)
- Casts between integer types of different width or signedness
- Shifts by an attacker-influenced count
- Computes an allocation size from external bytes
- Decodes a length-prefix from a network / IPC / file / image stream
- Computes image/video frame storage from width × height × bpp or stride × height
- Performs WebGPU/WebGL offset + size validation or buffer copy arithmetic
- Calculates Wasm effective addresses, array element sizes, or Memory64 bounds
- Uses `static_cast<uint32_t>` or `static_cast<unsigned>` on a `size_t` value
- Mixes signed and unsigned integers in comparisons, index math, or span construction
- Subtracts lengths/offsets without guarding against underflow (`a - b` where `a < b`)

## 2. The 10-question checklist

Answer ALL questions matching the triggers in Section 1.

### Q1. Are operands attacker-controlled?

Trace each operand to its source:
- Function parameter from a renderer-reachable entry → controlled
- Field set by IPC decode → controlled
- Field set by image / audio / video header parse → controlled
- Constant literal → not controlled
- Result of a previous `Checked<>` arithmetic → constrained, not free
- Result derived from `getrandom` / `RAND_bytes` → effectively bounded

If NO operand is attacker-controlled, this is not the right skill.

### Q2. What integer type holds the operation?

```cpp
size_t size = width * height * bytesPerPixel;
//             int     int      int
```

If the operands are `int32_t` (or `int`), the multiplication is
computed in 32-bit EVEN IF the destination is `size_t`. Bug.

```cpp
size_t size = static_cast<size_t>(width) * height * bytesPerPixel;
```

Now the multiplication is in `size_t`. Still risky if any pair
overflows `size_t`, but on 64-bit that's unreachable for typical
image dimensions. On 32-bit, still a bug.

### Q3. Is `Checked<>` used and consulted?

WebKit's `Checked<T>` (and `CheckedInt<T>`) traps overflow:
```cpp
Checked<size_t> size = Checked<size_t>(width) * height * bytesPerPixel;
if (size.hasOverflowed())
    return Failure;
return tryAllocate(size.value());
```

Bug shapes:
- Raw arithmetic into an allocation/index → fix with `Checked<>`
- `Checked<>` is built but `hasOverflowed()` is NEVER consulted
  before `value()` extraction → release-undefined behavior
- `Checked<>` is consulted on one path but not another

### Q4. Sign and width pitfalls

```cpp
(uint32_t)(int32_t)-1                   // → 0xFFFFFFFF (sign-ext via cast)
int32_t i = ...; size_t s = i;          // sign-extends if i is negative
int32_t a - int32_t b;  // a < b        // wraps to ~UINT32_MAX
1 << 31                                 // UB on int (signed); use 1u << 31
uint32_t x; x << n;     // n could be ≥ 32 → UB; mask n or check first
ssize_t r = read(...); size_t n = r;    // r=-1 → n is huge
```

All of these are common WebKit findings. Each is a separate
`INT_OVERFLOW_TO_OOB` candidate even without an explicit `*` or `+`.

### Q5. Image/video frame size overflow? (4 bugs in 5yr)

- `width × height × bytesPerPixel` computed without `Checked<>`?
- `stride × height` for NV12/I420/BGRA allocation?
- `VideoFrame` `storageSize` derived from `codedWidth`/`codedHeight`?

Grep: `width * height`, `bytesPerPixel`, `storageSize`, `stride` in
`image-decoders/`, `platform/graphics/`, `Modules/webcodecs/`.

### Q6. GPU/WebGL/WebGPU arithmetic overflow? (4 bugs in 5yr)

- `indirectOffset + size` can overflow and pass validation?
- `copyExternalImageToTexture` size computation in 32-bit?
- `RenderBundleEncoder` index validation arithmetic?

Grep: `indirectOffset`, `checkedSum`, `checkedProduct`,
`runIndexBufferValidation` in `Source/WebGPU/`.

### Q7. Wasm integer arithmetic overflow? (4 bugs in 5yr)

- Memory64 effective address wraps in 32-bit truncation?
- `arrayInitData` uses element count vs byte size (`count*elemSize` overflows)?
- `operationIterateResults` truncates i32 results?

Grep: `effectiveAddress`, `arrayInitData`, `operationIterateResults`,
`boundsCheck` in JSC `wasm/`.

### Q8. Truncation across type widths? (13 bugs in 5yr)

- `size_t` assigned to `uint32_t` losing high bits?
- `Deque`/`Vector` index stored as `unsigned` instead of `size_t`?
- Metal buffer pool index truncated from `size_t` to `int32_t`?
- Clipboard API narrowing conversions?

Grep: `static_cast<uint32_t>`, `static_cast<unsigned>`, `narrowing`,
`truncat` in target file.

### Q9. Signedness confusion? (20 bugs in 5yr)

- Negative `int32_t` sign-extends to huge `size_t`?
- `ssize_t` return value (`-1` on error) used as unsigned length?
- Negative z-index / scroll offset used as index?
- `Span` constructed with negative index → huge span?

Grep: `static_cast<size_t>`, `ssize_t`, `negative`, signed/unsigned
comparison warnings in target file.

### Q10. Subtraction underflow? (4 bugs in 5yr)

- `a - b` where `a < b` produces huge unsigned value?
- XPath substring position/length underflow?
- Buffer remaining = `total - consumed`, but `consumed > total`?

Grep: `position - 1`, `size - length`, `remaining` near subtraction
in target file.

## 3. CLAIM extraction

- `unchecked_op.file:line` — the arithmetic line itself
- `missing_check.file:line` — same line (replace with `Checked<>`)
  or earlier (clamp the operand before arithmetic)
- `bug_class` — `INT_OVERFLOW_TO_OOB` if the sink is in another method
  or reachable only at a later cycle. If sink is in same method, use
  the sink class per taxonomy precedence (e.g. `HEAP_OVERFLOW`)
- `patch_counterfactual` — wrap in `Checked<size_t>` with explicit
  `hasOverflowed()` check, or add a `numeric_limits<>::max()` bound,
  or constrain the input upstream

## 4. Reference materials

Read these from the same directory if you need depth:

- `intovf-pattern-catalog.md` — the 14-pattern taxonomy derived from
  5 years (741 commits, 128 classified) of WebKit integer overflow
  history. Each pattern has shape, trigger, sink, escalation,
  frequency, grep anchors, canonical code, and exemplar commits.
- `integer-promotion-traps.md` — C/C++ integer promotion rules,
  the 32-bit multiplication trap, sign extension cast table,
  truncation-on-assignment, shift UB, Checked<T> vs checkedProduct
  decision guide, JSC value→integer conversion safety table.
- `overflow-sink-map.md` — maps from arithmetic overflow sites to
  their downstream sinks (image decoder, WebGL, Wasm, IPC, CSS,
  String, Font, Audio, Canvas) with bug class and fix pattern.

## 5. What this skill won't help with

- OOB sink reachable in the same method → `webkit-bounds-audit`
- Lifetime bugs at the arithmetic site → `webkit-uaf-audit`
- Type-tag confusion driving an integer mismatch → `webkit-type-confusion-audit`

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
