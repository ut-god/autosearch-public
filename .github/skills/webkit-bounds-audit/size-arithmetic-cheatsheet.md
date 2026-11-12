# WebKit Size Arithmetic Cheatsheet

Reference for safe vs unsafe size/length/offset arithmetic. Consult when
classifying arithmetic in Q3 and Q11 of SKILL.md.

## Dangerous patterns

| Pattern | Risk | Fix |
|---------|------|-----|
| `width * height * bpp` in 32-bit | Overflow wraps to small value → undersized alloc | `Checked<size_t>` or `checkedProduct` |
| `static_cast<uint32_t>(size_t_val)` | Truncation drops high bits | Keep as size_t or validate < UINT32_MAX |
| `offset + length` unchecked | Sum overflows → passes bounds check | `Checked<size_t>` or check `offset <= max - length` |
| `toUInt32()` on JS value | Wraps (mod 2^32) — NOT clamped | Use `toLength()` for lengths (clamped 0..2^53-1) |
| Signed int as size → unsigned | Negative → huge positive | Validate non-negative before cast |
| `snprintf` return value as length | Returns would-have-written count, NOT actual bytes | Check against buffer size |

## WebKit safe arithmetic primitives

| API | Behavior on overflow | Use for |
|-----|---------------------|---------|
| `Checked<T>` | Traps or returns false on overflow | All size math |
| `checkedProduct(a, b)` | Returns std::optional — empty on overflow | width × height × bpp |
| `checkedSum(a, b)` | Same | offset + length |
| `RELEASE_ASSERT(x < bound)` | Crashes in release | Final bounds guard |
| `ASSERT(x < bound)` | Debug-only — NO protection | ❌ Never rely on for security |

## JSC value → size conversions

| Method | Range | Safe for size? |
|--------|-------|:---:|
| `toLength()` | 0..2^53-1, clamped | ✅ Yes |
| `toUInt32()` | 0..2^32-1, wraps (mod 2^32) | ❌ No — wraps |
| `toInt32()` | -2^31..2^31-1 | ❌ No — negative |
| `toIndex()` | 0..2^32-2 or "invalid" | ✅ If checked |

## StringImpl length limits

- `StringImpl::MaxLength` = `INT_MAX - 1` (2^31 - 2) — 32-bit length field
- Creating strings larger crashes via `RELEASE_ASSERT`
- `String::utf8()` can produce longer output than `length()` — up to 3× for BMP
