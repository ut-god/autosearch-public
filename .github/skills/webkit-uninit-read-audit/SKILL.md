---
name: webkit-uninit-read-audit
description: Deep audit playbook for UNINIT_READ bugs in WebKit. Consult when the target method allocates uninitialized memory (malloc, fastMalloc, alloca, raw new), copies a struct that may contain uninitialized padding, returns a buffer whose initialization depends on an early-exit branch, or serializes a field that may not have been written. Returns the uninitialized-read site and the missing zeroing/initialization.
---

# WebKit Uninitialized Read Audit

`UNINIT_READ` matters when the read value either reaches an attacker-
observable channel (info leak) or feeds a security decision (bypass).
Pure internal uninit reads with no observation are usually noise —
audit Q4 first to confirm impact before claiming.

## 1. When this skill applies

Consult when the method:
- Calls `fastMalloc` / `malloc` / `alloca` / `new T[n]` (raw allocation) → Q1
- Memcpys a struct with padding bytes (possible padding-leak) → Q2, Q5
- Has an early return that leaves an out-param partially initialized → Q3
- Serializes a struct via `memcpy` or IPC encode → Q5
- Reads from a `Vector` before `reserveInitialCapacity` / `resize` → Q1
- Casts a buffer view over uninitialized backing memory → Q1
- Calls `glReadPixels` / `getImageData` / clipboard read into a buffer → Q6
- Returns a `RefPtr<ArrayBuffer>` / `String` constructed from raw alloc → Q9
- Uses `ArgumentCoder` / `encodeBytes` / `encode(reinterpret_cast` on a struct → Q5
- Writes into a graphics buffer with possible early-return path → Q6
- Defines a constructor that may miss member fields → Q7
- Grows or creates a `Butterfly` / `ArrayStorage` → Q8
- Calls `String::createUninitialized` / `uninitializedCopy` / `uninitializedFill` → Q9

Answer ALL questions whose triggers match the code under audit.

## 2. The 9-question checklist

### Q1. Is the allocation zeroed?

| Allocator / construction | Zeroes? |
|---|---|
| `malloc(n)`, `fastMalloc(n)`, `tryFastMalloc(n)` | NO |
| `calloc(n, sz)`, `fastZeroedMalloc(n)`, `tryFastZeroedMalloc(n)` | yes |
| `new T[n]` for trivial `T` (`int`, `char`) | NO |
| `new T[n]` for non-trivial `T` (default-init) | calls `T()` per element |
| `Vector<T>(n)` for non-trivial `T` | calls `T()` per element |
| `Vector<T>(n)` for trivial `T` | NO (capacity allocated, no value-init) |
| `Vector<T>::resize(n)` for trivial `T` | NO unless explicit fill |
| `alloca(n)` | NO |
| `std::array<T, N>{}` (value-init) | yes |
| `std::array<T, N> arr;` | NO for trivial T |
| `IOSurface::createBuffer` | implementation-defined; assume NO |
| `WebCore::SharedBuffer::create(size)` | yes (zero-fills) |

If the buffer comes from a NO-row allocator and the method doesn't
explicitly fill it before observation → uninit candidate.

### Q2. Padding bytes in serialized struct

```cpp
struct Foo {
    uint8_t a;     // 1 byte
    /* 3 bytes implicit padding */
    uint32_t b;    // 4 bytes
};

Foo foo;
foo.a = 1;
foo.b = 2;
encoder.encodeBytes(reinterpret_cast<uint8_t*>(&foo), sizeof(foo));
// ❌ encodes 3 padding bytes whose value is whatever was on the stack
```

This is the classic info-leak primitive. Fix:
- `memset(&foo, 0, sizeof(foo))` before fill (cheapest)
- Encode field-by-field instead of as bytes (most robust)
- Use `__attribute__((packed))` to remove padding (rarely correct)

### Q3. Partial initialization on error

```cpp
bool decode(Foo& out) {
    if (!decoder.decode(out.a))
        return false;
    if (!decoder.decode(out.b))
        return false;  // ❌ caller may use out.a / out.b assuming false
    return true;
}
```

Caller pattern matters:
- `Foo f; if (decode(f)) use(f);` → safe
- `Foo f; decode(f); use(f);` → bug, `out` is partial
- `Foo f = ...; decode(f);` → safe if default value is well-defined

Audit BOTH the decoder and at least 2-3 call sites to determine
whether the partial-init is observable.

### Q4. Does the value reach an attacker-observable channel?

`UNINIT_READ` matters when the value:
- Returns to JS via a binding (info leak across origin)
- Is sent over IPC (info leak across process)
- Is written to disk / network (info leak persistent)
- Influences a security check (`isTrusted`, capability flag) → bypass
- Is hashed or compared as a key (cache poisoning)
- Is included in a stack/heap address that leaks through any of the above

If the value is consumed and discarded internally with no observation,
severity is Low or `n/a`. Don't file noise claims.

### Q5. IPC serialization of struct with padding?

*1+ bugs in 5yr.* `ArgumentCoder` encoding a struct as raw bytes is a
classic padding-leak vector.

- Does `ArgumentCoder` encode a struct as raw bytes (`memcpy` / `encodeBytes`)?
- Does the struct have implicit padding from alignment?
- Are bit-fields involved? (bit-field padding is especially tricky —
  the compiler may leave unused bits in the packing word uninitialized)
- Fix: encode field-by-field, or `memset(&s, 0, sizeof(s))` before filling

**Grep:** `encodeBytes`, `encode(reinterpret_cast`, `ArgumentCoder` in IPC code.

### Q6. Graphics buffer returned without full initialization?

*2+ bugs in 5yr.* Buffers backing canvas / WebGL / IOSurface can leak
stale content if not fully written before exposure.

- Does `glReadPixels` / `getImageData` write into a `fastMalloc`'d buffer?
- Is there an early-return path where the buffer is partially filled?
- IOSurface: is the mapped region zeroed before use?
- Alpha channel: is it explicitly set or left from previous content?

**Grep:** `glReadPixels`, `getImageData`, `IOSurface`, `createImageBuffer`
in `WebCore/platform/graphics/`.

### Q7. Missing field initialization in constructor?

*19+ bugs in 5yr.* The most common uninit-read variant by volume.

- Does the constructor initialize ALL member fields?
- Are there fields added after the initial constructor was written?
- Bit-fields: are all bits in the bitfield word initialized?
- C++ default-init of trivial types (`int`, pointer) leaves them
  uninitialized — only value-init (`T()` or `= 0`) zeroes them

**Grep:** look at constructor initializer list vs field declarations
in the header.

### Q8. JSC Butterfly / ArrayStorage gap/hole not zeroed?

*3+ bugs in 5yr.* Butterfly growth can leave a gap between old and new
`publicLength` containing stale heap data.

- When Butterfly grows, is the gap between old and new `publicLength` zeroed?
- Array holes (deleted indices): do they contain `JSValue()` or stale data?
- `JSArray::tryCreate`: is the initial butterfly fully initialized?

**Grep:** `clearOptimalVectorLengthGap`, `Butterfly::create`,
`JSArray::tryCreate`, `publicLength` vs `vectorLength`.

### Q9. String::createUninitialized not fully written?

*4+ bugs in 5yr.* `createUninitialized` hands back a writable buffer
that the caller MUST fill completely before the string is exposed.

- Does the caller of `createUninitialized` fill ALL bytes before the
  string is exposed?
- Is there an early-return between `createUninitialized` and the fill loop?
- `operationJSToWasmEntryWrapperBuildReturnFrame`: classic example of
  partial init

**Grep:** `createUninitialized`, `uninitializedCopy`,
`uninitializedFill` in WTF/JSC.

## 3. CLAIM extraction

- `unchecked_op.file:line` — the read site (the uninit access, NOT the
  allocation)
- `missing_check.file:line` — where initialization should occur
- `bug_class` — `UNINIT_READ` always; severity from Q4
- `patch_counterfactual` — typically `memset(&x, 0, sizeof(x))` before
  fill, OR change to `fastZeroedMalloc`, OR add explicit field init,
  OR refactor to `Foo{}` value-init

## 4. Reference materials

Read these from the same directory if you need depth:

- `uninit-pattern-catalog.md` — the 10-pattern taxonomy derived from
  5 years (357 commits, 93 classified) of WebKit uninit-read history.
  Each pattern has shape, trigger, sink, escalation, frequency, grep
  anchors, canonical code, and exemplar commits.
- `allocation-init-cheatsheet.md` — 21-row allocator zeroing table,
  struct padding rules with alignment/bit-field gotchas, observation
  channel severity guide (IPC, JS binding, network, GPU, clipboard).

## 5. WebKit-specific anchors (where to grep)

- IPC `ArgumentCoders` for non-zero-init structs (especially with
  bit-fields — bit-field padding is a common source)
- WebGL: `glReadPixels` into uninitialized backing storage
- Canvas `getImageData`: alpha channel sometimes stale
- Crypto: any nonce / IV computed via raw alloc
- JSC: `ButterflyImpl` growth without value-init
- `RawBuffer` / `RefPtr<DataView>` constructed from `fastMalloc`
- `IOSurface` / GPU-mapped buffers shared with another process
- `String::createUninitialized` — name says it; verify the caller
  initializes EVERY byte before exposure

## 6. What this skill won't help with

- Uninit read in scope-local memory not crossing observation → not a CVE
- OOB read of unrelated allocation → `webkit-bounds-audit`
- UAF where the dangling memory happens to be uninit → `webkit-uaf-audit`
  (the underlying bug is the dangling reference, not the uninit value)

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
