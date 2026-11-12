# WebKit Allocation & Initialization Cheatsheet

Reference for which allocators zero memory and which don't, struct
padding rules, and observation channels for uninit data. Consult when
classifying allocations in Q1, padding in Q2/Q5, and impact in Q4 of
SKILL.md.

## 1. Allocator initialization table

| Allocator / construction | Zeroes? | Notes |
|---|:---:|---|
| `malloc(n)` | NO | C library — never zeroes |
| `fastMalloc(n)` / `tryFastMalloc(n)` | NO | bmalloc backend — raw pages recycled |
| `fastZeroedMalloc(n)` / `tryFastZeroedMalloc(n)` | YES | Explicit `memset(0)` inside |
| `fastCalloc(count, sz)` | YES | Like `calloc` — zeroed + overflow-safe |
| `bmalloc::api::malloc(n)` | NO | Low-level bmalloc — same as `fastMalloc` |
| `new T` (trivial `T`: `int`, `char*`, POD) | NO | Default-init → indeterminate |
| `new T` (non-trivial `T` with default ctor) | calls ctor | Ctor must init all fields |
| `new T[n]` (trivial `T`) | NO | Array of indeterminate values |
| `new T[n]` (non-trivial `T`) | calls `T()` | Per-element default-init |
| `Vector<T>::resize(n)` (trivial `T`) | NO | Extends size, no value-init |
| `Vector<T>::resize(n)` (non-trivial `T`) | calls `T()` | Per-element construction |
| `Vector<T>::grow(n)` | NO | Capacity only — no elements constructed |
| `Butterfly::create` / `tryCreate` | depends | Must call `clearOptimalVectorLengthGap` to zero gap |
| `String::createUninitialized(len, buf)` | NO | Returns writable `buf` — caller MUST fill all bytes |
| `ArrayBuffer::create(byteLength)` | YES | Zeroed per spec (Web IDL) |
| `SharedBuffer::create(size)` | YES | Zero-fills backing store |
| `IOSurface` map | NO | Assume prior content; must zero explicitly |
| `alloca(n)` | NO | Stack allocation — stale stack data |
| `mmap(MAP_ANONYMOUS)` | YES | Kernel zeroes pages before mapping |
| `std::array<T, N>{}` (value-init) | YES | Braces trigger value-init for all elements |
| `std::array<T, N> arr;` (default-init) | NO | Trivial `T` left indeterminate |

**Rule of thumb:** if the allocator name doesn't contain "zero",
"calloc", or "create" (for spec-mandated types), assume NO and
verify manually.

## 2. Struct padding rules

### Where padding is inserted

C/C++ compilers insert padding to satisfy alignment requirements:

```
struct Example {
    uint8_t  a;     // offset 0, size 1
    // 3 bytes padding (b requires 4-byte alignment)
    uint32_t b;     // offset 4, size 4
    uint8_t  c;     // offset 8, size 1
    // 3 bytes tail padding (struct alignment = max member = 4)
};
// sizeof(Example) == 12, but only 6 bytes are "real" data
```

### Alignment of common field types

| Type | Alignment (typical) |
|------|:---:|
| `bool`, `uint8_t`, `int8_t`, `char` | 1 |
| `uint16_t`, `int16_t` | 2 |
| `uint32_t`, `int32_t`, `float` | 4 |
| `uint64_t`, `int64_t`, `double` | 8 |
| `T*` (pointer) | 4 (32-bit) / 8 (64-bit) |
| `std::atomic<T>` | same as `T` (usually) |

### Padding insertion rules

1. **Between fields:** pad so each field starts at its natural alignment
2. **At end of struct:** pad so `sizeof(struct)` is a multiple of the
   largest member alignment (so arrays of structs stay aligned)
3. **Bit-fields:** packed into the underlying integer type; unused bits
   within the packing word are NOT guaranteed zero — this is the
   sneakiest padding source

### Bit-field packing gotchas

```cpp
struct Flags {
    uint32_t isSecure : 1;
    uint32_t isHTTPS  : 1;
    // 30 bits of padding in this uint32_t word — NOT zeroed by
    // setting isSecure and isHTTPS alone
};
```

If `Flags` is serialized as raw bytes, the 30 unused bits leak stack
or heap data. Always `memset(&flags, 0, sizeof(flags))` before
setting individual bit-fields.

### How to audit struct padding

1. **`static_assert(sizeof(Foo) == expected)`** — if someone already
   added this, the expected value tells you the packed vs padded story
2. **`offsetof(Foo, field)`** — check gaps between consecutive fields
3. **Compiler flags:** `-Wpadded` (Clang/GCC) warns on implicit padding
4. **`pahole`** tool — shows struct layout with padding holes

### Fix patterns

| Pattern | When to use |
|---------|-------------|
| `memset(&s, 0, sizeof(s))` before fill | Cheapest; works for any struct |
| Field-by-field encode | Most robust for IPC — immune to layout changes |
| `= {}` value-init | C++ aggregate init — zeroes padding |
| `[[no_unique_address]]` | Reduces padding from empty base / member |
| Reorder fields by descending alignment | Minimizes internal padding |
| `__attribute__((packed))` | Removes padding but hurts perf and may cause UB on some archs |

## 3. Observation channels (where uninit data can leak)

Uninit data is only a security bug if it reaches an attacker-observable
channel. Map every uninit candidate to one of these:

| Channel | Scope | Severity |
|---------|-------|----------|
| **IPC message** | Cross-process (renderer → browser, or vice versa) | High — sandbox escape info leak |
| **JS binding return** | Cross-origin (e.g., `getImageData` to JS) | High — same-origin bypass |
| **Network / disk write** | Persistent / remote | Critical — data leaves device |
| **GPU shared memory** | Cross-process (GPU process ↔ renderer) | High — similar to IPC |
| **Clipboard** | Cross-app | Medium — user-triggered but wide reach |
| **Crypto nonce / IV** | Weakens randomness | Medium–High — depends on protocol |
| **Security check input** | In-process decision | Variable — bypass if uninit ≠ expected |
| **Internal-only, no observation** | None | Low / n/a — not a CVE |

### Quick triage

1. Trace the uninit value forward from the allocation to its first use
2. If it hits any channel above except "internal-only" → file the claim
3. If it's internal-only, check whether the value influences a branch
   that gates a security decision — if yes, still file
4. If purely internal with no observation and no security branch → skip
