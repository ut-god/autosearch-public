# C/C++ Integer Promotion & Conversion Traps in WebKit

Reference for implicit promotions, narrowing conversions, and shift UB that
create integer-overflow vulnerabilities. Consult alongside SKILL.md when
auditing arithmetic expressions.

---

## 1 · Implicit promotion rules (usual arithmetic conversions)

When two operands of different type meet in an expression the compiler
silently converts the "smaller" or "more signed" operand:

| Operand A | Operand B | Result type | Gotcha |
|-----------|-----------|-------------|--------|
| `int` | `int` | `int` | Stays 32-bit — overflows silently |
| `int` | `unsigned` | `unsigned` | Negative `int` becomes huge positive |
| `int` | `size_t` | `size_t` | Negative `int` → 0xFFFFFFFF… |
| `uint32_t` | `uint32_t` | `uint32_t` | Still 32-bit — no auto-widen |
| `uint32_t` | `size_t` | `size_t` | OK — zero-extends, safe |
| `int32_t` | `size_t` | `size_t` | ❌ Negative sign-extends to huge |
| `int` | `long long` | `long long` | Widened — safe if no prior overflow |

**Key rule:** the result type of `a OP b` is chosen *before* the result
is assigned. An `int * int` product overflows at 32 bits even when the
destination is `size_t`.

---

## 2 · The 32-bit multiplication trap

```cpp
int width  = untrusted();   // e.g. 65536
int height = untrusted();   // e.g. 65536
size_t bytes = width * height * 4;
//            ^^^^^^^^^^^^^^^^^^^
//  Step 1: width * height  → int * int = int → OVERFLOW (2^32, wraps to 0)
//  Step 2: 0 * 4           → int * int = int → 0
//  Step 3: assign 0 to size_t           → 0
//  Result: allocate(0) → write 16 GB → HEAP_OVERFLOW
```

**Promotion chain:**

```
int × int  ──→  int (32-bit, can overflow)
            │
            ╰─→  × int  ──→  int (still 32-bit)
                          │
                          ╰─→  assign to size_t  (damage already done)
```

**Fix — force 64-bit before the first multiply:**

```cpp
size_t bytes = static_cast<size_t>(width) * height * 4;   // all operands promote to size_t
// or, best:
auto bytes = checkedProduct<size_t>(width, height, 4);     // returns std::optional
```

---

## 3 · Sign extension on cast

When a signed value is cast to a wider unsigned type the sign bit fills
all new high bits:

| Expression | Value (hex) | Decimal |
|-----------|-------------|---------|
| `(size_t)(int32_t)-1` | `0xFFFFFFFFFFFFFFFF` | 2^64 − 1 |
| `(size_t)(int32_t)-2` | `0xFFFFFFFFFFFFFFFE` | 2^64 − 2 |
| `(uint64_t)(int16_t)-1` | `0xFFFFFFFFFFFFFFFF` | 2^64 − 1 |
| `(uint32_t)(int8_t)-1` | `0xFFFFFFFF` | 2^32 − 1 |
| `(size_t)(uint32_t)-1` | `0x00000000FFFFFFFF` | 2^32 − 1 (zero-extend — safe) |

**Dangerous cast patterns:**

| Cast | Risk | Safe alternative |
|------|------|-----------------|
| `static_cast<size_t>(int32_var)` | Negative → huge positive | Validate `>= 0` first |
| `static_cast<size_t>(signedLen - 1)` | If `signedLen == 0` → 0xFFFF… | Check `signedLen > 0` before subtract |
| `implicit conversion in function arg` | `void f(size_t n)` called with `int` | Explicit cast + validation at call site |

**Grep anchors:**

```
static_cast<size_t>
static_cast<unsigned>
(size_t)
(unsigned)
```

---

## 4 · Truncation on assignment

Assigning a wider value to a narrower type silently drops high bits:

```cpp
size_t bigVal = 0x1'0000'0000ULL;   // 4 GB + 0
uint32_t x = bigVal;                 // x == 0  (silent truncation)
uint32_t y = static_cast<uint32_t>(bigVal);  // same — cast doesn't validate
```

| Source | Destination | Bits lost | Risk |
|--------|------------|-----------|------|
| `size_t` (64-bit) | `uint32_t` | upper 32 | Length wraps → undersized alloc |
| `size_t` | `int` | upper 33 (sign) | Wrap + possible negative |
| `uint64_t` | `uint16_t` | upper 48 | Index wraps → OOB |
| `int64_t` | `int32_t` | upper 32 | Value changes sign or magnitude |

**Fix pattern — validate then cast:**

```cpp
if (totalSize > std::numeric_limits<uint32_t>::max())
    return std::nullopt;
uint32_t size32 = static_cast<uint32_t>(totalSize);
```

Or use `Checked<uint32_t>`:

```cpp
Checked<uint32_t> size32 = totalSize;  // overflows if > UINT32_MAX
if (size32.hasOverflowed())
    return std::nullopt;
```

**Grep anchors:**

```
static_cast<uint32_t>
static_cast<int>
static_cast<unsigned>
= static_cast<uint16_t>
```

---

## 5 · Shift undefined behaviour

| Expression | Status | Why |
|-----------|--------|-----|
| `1 << 31` | ❌ UB (C++17 & earlier) | Signed `int 1` shifted into sign bit |
| `1 << 32` | ❌ UB | Shift count ≥ bitwidth of `int` (32) |
| `1u << 31` | ✅ OK | Unsigned — no sign-bit issue |
| `1u << 32` | ❌ UB | Shift count ≥ bitwidth of `unsigned` |
| `1ULL << 63` | ✅ OK | Unsigned 64-bit, bit 63 is valid |
| `x << n` where `n < 0` | ❌ UB | Negative shift count |
| `x << n` where `n >= 64` | ❌ UB | Shift count ≥ bitwidth |

**Common WebKit patterns:**

```cpp
// BAD — UB if bit >= 32
uint32_t mask = 1 << bit;

// GOOD
uint32_t mask = 1u << bit;          // still need bit < 32

// BAD — shift by untrusted amount
unsigned flags = value << shift;     // UB if shift >= 32

// GOOD — clamp or validate
if (shift < 32)
    unsigned flags = 1u << shift;
```

**Grep anchors:**

```
<< 31
<< 32
1 <<
1u <<
```

---

## 6 · WebKit safe arithmetic: Checked\<T\> vs checkedProduct / checkedSum

| API | Type | Overflow behaviour | Use when |
|-----|------|-------------------|----------|
| `Checked<T>` | Type wrapper | Stores overflow flag; `.hasOverflowed()` to query | Accumulating multiple operations: `Checked<size_t> total; total += a; total *= b;` |
| `checkedProduct(a, b, ...)` | Free function → `std::optional<T>` | Returns `std::nullopt` on overflow | One-shot multiply: `auto bytes = checkedProduct<size_t>(w, h, bpp);` |
| `checkedSum(a, b, ...)` | Free function → `std::optional<T>` | Returns `std::nullopt` on overflow | One-shot add: `auto end = checkedSum<size_t>(offset, length);` |

**Decision guide:**

```
Need a single product or sum?
  └─→ checkedProduct / checkedSum (simpler, returns optional)

Need a chain of mixed +, ×, shifts?
  └─→ Checked<T> wrapper (tracks overflow across operations)

Need to pass a "might-overflow" value around?
  └─→ Checked<T> (embeds the overflow flag in the value)
```

**Example — Checked\<T\>:**

```cpp
Checked<size_t> total = width;
total *= height;
total *= bytesPerPixel;
if (total.hasOverflowed())
    return { };
auto* buffer = tryAllocate(total.value());
```

**Example — checkedProduct:**

```cpp
auto total = checkedProduct<size_t>(width, height, bytesPerPixel);
if (!total)
    return { };
auto* buffer = tryAllocate(*total);
```

**Grep anchors:**

```
Checked<
checkedProduct
checkedSum
hasOverflowed
```

---

## 7 · JSC value → native integer conversions

| Method | Semantic | Output range | Wraps? | Clamps? | Safe for size? |
|--------|----------|-------------|:------:|:-------:|:--------------:|
| `toUInt32(exec)` | ES ToUint32 — mod 2^32 | 0 .. 2^32−1 | ✅ Yes | ❌ No | ❌ No — wraps |
| `toInt32(exec)` | ES ToInt32 — mod 2^32 then sign | −2^31 .. 2^31−1 | ✅ Yes | ❌ No | ❌ No — negative/wraps |
| `toLength(exec)` | ES ToLength — clamp 0..2^53−1 | 0 .. 2^53−1 | ❌ No | ✅ Yes | ✅ Yes |
| `toIndex(exec)` | ES array index — 0..2^32−2 or invalid | 0 .. 2^32−2 | ❌ No | ❌ No | ✅ If error checked |
| `toNumber(exec)` | ES ToNumber — double | full double range | N/A | ❌ No | ❌ No — float rounding |
| `toInteger(exec)` | ES ToInteger — truncate to int | full double int range | ❌ No | ❌ No | ❌ No — can be negative |

**Common vulnerability pattern:**

```cpp
// BAD — toUInt32 wraps: JS value -1 → 0xFFFFFFFF → huge alloc or bypass
uint32_t length = args[0].toUInt32(exec);
auto* buf = tryAllocate(length * elementSize);   // may also overflow

// GOOD — toLength clamps, then checked multiply
size_t length = args[0].toLength(exec);
RETURN_IF_EXCEPTION(scope, { });
auto bytes = checkedProduct<size_t>(length, elementSize);
if (!bytes)
    return throwRangeError(exec, scope, "too large"_s);
```

**Grep anchors:**

```
toUInt32
toInt32
toLength
toIndex
toNumber
toInteger
```
