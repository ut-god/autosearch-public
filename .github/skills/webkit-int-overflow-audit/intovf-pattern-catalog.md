# WebKit Integer-Overflow Pattern Catalog

> **Methodology**: Bottom-up classification of 741 integer-overflow-related commits
> across WebKit (2021-01-01 → 2026-05-31). Each commit was tagged by keyword and
> diff-level structural analysis, then merged into deduplicated pattern buckets.
> The result is a taxonomy of **14 recurring integer-overflow shapes** that account
> for 128 of the classified commits. This catalog replaces the earlier
> individual-CVE listing with a structural approach: audit for *patterns*, not
> individual bugs.

---

## Summary table

| ID | Pattern | 5yr Count |
|----|---------|:---------:|
| I-CSS | CSS/layout value overflow | 29 |
| I-SIGN | Signedness confusion | 24 |
| I-TRUNC | Width truncation (64→32, 32→16, float→int) | 20 |
| I-CHECKED | Checked\<T\> adoption / fix | 10 |
| I-WRAP | Modular wrap-around | 10 |
| I-GPU | GPU/WebGL/WebGPU size overflow | 6 |
| I-UNDERFLOW | Subtraction underflow | 6 |
| I-IMGSIZE | Image/video frame size overflow | 5 |
| I-WASM | Wasm arithmetic overflow | 5 |
| I-IPC | IPC message size overflow | 4 |
| I-TEMPORAL | Temporal/Date arithmetic overflow | 3 |
| I-ALLOC | Allocation size overflow | 3 |
| I-STRING | String length overflow | 2 |
| I-XML | XML/XPath arithmetic overflow | 1 |

---

## Pattern entries

---

### I-CSS: CSS/layout value overflow
**Shape**: An arithmetic operation on CSS layout values (LayoutUnit, font metrics, line-box geometry) overflows the fixed-point or integer representation, producing a wrapped or negative value.
**Trigger**: Unary negation of `INT_MIN`, multiplication of large layout coordinates, or addition of padding/margin values that exceed `LayoutUnit::max()`.
**Sink**: The overflowed value is used as a position, width, or clip rect — causing mis-rendering, infinite loops, or (in ~5 memory-safety-relevant cases) out-of-bounds writes into paint buffers.
**Escalation**: DoS, OOB_WRITE (rare), INT_OVERFLOW_TO_OOB (rare)

> **Note**: 29 commits match this pattern, but the majority (~24) are
> rendering-correctness fixes (visual glitches, wrong clipping, infinite layout
> loops). Only a subset (~5) are memory-safety-relevant — those where the
> overflowed value feeds into an allocation size, buffer index, or memcpy length.
> The rest are included because the same arithmetic shapes can become
> security-relevant in different call-site contexts.

**5yr frequency**: 29 commits (2021–2026)
**Affected dirs**: `Source/WebCore/rendering/`, `Source/WebCore/platform/graphics/`, `Source/WebCore/css/`, `Source/WebCore/layout/`
**Grep anchors**:
```sh
rg "LayoutUnit|intMinForLayoutUnit|intMaxForLayoutUnit" -n Source/WebCore/rendering
rg "saturatedAddition|saturatedSubtraction" -n Source/WebCore/platform
rg "clampTo<int>" -n Source/WebCore/rendering
```
**Canonical code**:
```cpp
// ❌ bad — unary negation of LayoutUnit can overflow at INT_MIN
LayoutUnit flipped = -value;  // undefined if value == INT_MIN

// ✅ safe — use saturated negation or clamp
LayoutUnit flipped = -value.clampNegativeToZero();
// or
LayoutUnit flipped = LayoutUnit() - value;  // saturated subtraction
```
**Exemplar commits**:
- `2c3e402a8ea0` — LayoutUnit unary minus −INT_MIN overflow
- `3001e5dd0235` — text-overflow ellipsis RTL truncation

---

### I-SIGN: Signedness confusion
**Shape**: A signed integer is implicitly converted to unsigned (or vice versa), producing a large positive value from a small negative one or a negative index from an unsigned value.
**Trigger**: Comparison between signed and unsigned types, assignment of a signed value to an unsigned variable, or sign-extension when casting pointers to integers on 32-bit platforms.
**Sink**: The mis-interpreted value is used as an array index, loop bound, allocation size, or bit-flag mask, causing OOB access or logic corruption.
**Escalation**: OOB_READ, OOB_WRITE, HEAP_OVERFLOW, DoS
**5yr frequency**: 24 commits (2021–2026)
**Affected dirs**: `Source/WebCore/platform/audio/`, `Source/WTF/wtf/`, `Source/JavaScriptCore/`, `Source/WebCore/platform/network/`
**Grep anchors**:
```sh
rg -- "-Wsign-compare|-Wsign-conversion" -n Source/
rg "unsignedCast|checkedCast" -n Source/WTF/wtf
rg "static_cast<unsigned>" -n Source/WebCore/platform/audio
```
**Canonical code**:
```cpp
// ❌ bad — negative span becomes huge unsigned
void process(int spanSize) {
    for (unsigned i = 0; i < spanSize; ++i)  // if spanSize < 0, wraps
        buffer[i] = 0;
}

// ✅ safe — validate or use matching types
void process(int spanSize) {
    if (spanSize <= 0)
        return;
    for (int i = 0; i < spanSize; ++i)
        buffer[i] = 0;
}
```
**Exemplar commits**:
- `19e127b1e23d` — DirectConvolver negative span index
- `71d38ea60229` — WTF::unsignedCast utility
- `a72d685c4e9c` — sign-extended pointer-to-uint64 on 32-bit
- `bb40425085b9` — signed int for UInt64 bit flags
- `f13f32fbbf8d` — -Wsign-compare int vs unsigned in URL::setPath

---

### I-TRUNC: Width truncation (64→32, 32→16, float→int)
**Shape**: A value in a wider type (uint64_t, size_t on 64-bit, double/float) is assigned or cast to a narrower type (uint32_t, unsigned, int16_t, int), silently discarding high bits or fractional parts.
**Trigger**: Implicit narrowing conversions, explicit `static_cast` to a smaller type, or storing a 64-bit value in a 32-bit struct field. Common on mixed 32-bit/64-bit platforms where `size_t` width varies.
**Sink**: The truncated value is used as an allocation size (allocating too little), a buffer length (short copy/read), or an index (wrapping to a valid but wrong offset).
**Escalation**: HEAP_OVERFLOW, OOB_WRITE, OOB_READ, INT_OVERFLOW_TO_OOB
**5yr frequency**: 20 commits (2021–2026)
**Affected dirs**: `Source/WebCore/platform/graphics/`, `Source/WebKit/`, `Source/JavaScriptCore/wasm/`, `Source/WebCore/html/`, `Source/WTF/wtf/`, `Source/WebGPU/`
**Grep anchors**:
```sh
rg "static_cast<uint32_t>|static_cast<unsigned>|static_cast<int>" -n Source/JavaScriptCore/wasm
rg "size_t.*unsigned|uint64_t.*uint32_t" -n Source/WebKit
rg "checkedProduct|checkedSum|Checked<" -n Source/WebCore/platform/graphics
```
**Canonical code**:
```cpp
// ❌ bad — 64-bit size truncated to 32-bit
uint32_t bufSize = static_cast<uint32_t>(totalBytes);  // high bits lost
auto buffer = malloc(bufSize);  // allocates too little if totalBytes > 4GB

// ✅ safe — validate or use Checked<>
Checked<uint32_t, RecordOverflow> bufSize = totalBytes;
if (bufSize.hasOverflowed())
    return;
auto buffer = malloc(bufSize.value());
```
**Exemplar commits**:
- `4834ca819f83` — ImageBuffer logicalSize float→int truncation
- `4c0ebd7617b5` — Clipboard uint64→size_t on 32-bit
- `5282ec7af05e` — VideoDecoder ULL→UL narrowing
- `95959f01b05f` — Wasm Memory64 atomic ops 64→32 truncation
- `afc44e359ac3` — IPInt slow path .i32 union member truncates 64-bit
- `7e3461d08115` — Deque size_t→unsigned
- `4369d90c86f6` — Metal buffer pool size_t→int32
- `aff0d180af6e` — TextCodecUTF8 size_t→unsigned

---

### I-CHECKED: Checked\<T\> adoption / fix
**Shape**: Code that previously performed raw arithmetic on sizes or counts is migrated to use `WTF::Checked<T>` (or `checkedSum`/`checkedProduct` helpers), or an existing `Checked<T>` usage is found to be incorrect (wrong width, missing overflow check on the result).
**Trigger**: A multiplication or addition of attacker-influenced dimensions (width × height × bytesPerPixel, offset + size) can overflow; the fix wraps the arithmetic in `Checked<>` and checks `hasOverflowed()`.
**Sink**: The unchecked product/sum is passed to an allocator, `memcpy` size, or array index.
**Escalation**: HEAP_OVERFLOW, OOB_WRITE, INT_OVERFLOW_TO_OOB
**5yr frequency**: 10 commits (2021–2026)
**Affected dirs**: `Source/WebCore/platform/graphics/`, `Source/WebGPU/`, `Source/WebCore/html/canvas/`, `Source/WTF/wtf/`
**Grep anchors**:
```sh
rg "Checked<|checkedSum|checkedProduct|hasOverflowed" -n Source/WebCore/platform/graphics
rg "Checked<uint32_t>|Checked<size_t>|Checked<uint64_t>" -n Source/WebGPU
rg "RecordOverflow" -n Source/WTF/wtf
```
**Canonical code**:
```cpp
// ❌ bad — raw multiplication overflows silently
size_t bytes = width * height * 4;
auto buffer = malloc(bytes);

// ✅ safe — Checked<> catches overflow
Checked<size_t, RecordOverflow> bytes = Checked<size_t>(width) * height * 4;
if (bytes.hasOverflowed())
    return;
auto buffer = malloc(bytes.value());
```
**Exemplar commits**:
- `0f73fd29f852` — WebGPU checkedSum uint32 vs uint64
- `3ee1b4aadb0f` — readPixelsImpl checkedProduct crash
- `535e0d52d4e8` — Drop Vector overloads taking Checked\<size_t\>

---

### I-WRAP: Modular wrap-around
**Shape**: An unsigned (or fixed-width) arithmetic operation wraps around modulo 2^N, producing a small value from what should be a large one. The wrapped result passes a subsequent bounds check that would have failed with the true value.
**Trigger**: Addition or multiplication of two large unsigned values whose true sum/product exceeds `UINT32_MAX` or `UINT64_MAX`, wrapping to a small value that satisfies `result < buffer.size()`.
**Sink**: The wrapped value is used as a buffer offset, loop count, or allocation size.
**Escalation**: HEAP_OVERFLOW, OOB_WRITE, OOB_READ
**5yr frequency**: 10 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/wasm/`, `Source/WebCore/platform/graphics/filters/`, `Source/WebCore/platform/graphics/avcodec/`, `Source/WebKit/`
**Grep anchors**:
```sh
rg "effectiveAddress|area\(\)" -n Source/JavaScriptCore/wasm
rg "order\(\)\.width\(\).*order\(\)\.height\(\)" -n Source/WebCore/platform/graphics/filters
rg "BitstreamReader" -n Source/WebCore/platform/graphics/avcodec
```
**Canonical code**:
```cpp
// ❌ bad — area() wraps on large order values
unsigned area = order.width() * order.height();  // wraps if > UINT_MAX
auto kernel = Vector<float>(area);  // too-small allocation

// ✅ safe — use Checked<> for the multiplication
Checked<unsigned, RecordOverflow> area = Checked<unsigned>(order.width()) * order.height();
if (area.hasOverflowed())
    return;
auto kernel = Vector<float>(area.value());
```
**Exemplar commits**:
- `370255eb46e7` — IPInt Memory64 effective address wraps
- `7f3400f5de0c` — SVG feConvolveMatrix order.area() wraps
- `b05fd50ce4ab` — H265 log2_max wrap in BitstreamReader
- `de9aadffaee1` — browser.tabs.create double→unsigned wrap

---

### I-GPU: GPU/WebGL/WebGPU size overflow
**Shape**: A GPU API validation path computes buffer sizes, offsets, or vertex counts using attacker-controlled values; the arithmetic overflows, causing the validation to pass when it should fail.
**Trigger**: Multiplying vertex count × stride, adding offset + size, or computing texture dimensions × bytesPerPixel — where the inputs come from JavaScript via the WebGPU or WebGL API.
**Sink**: The overflowed value is passed to the GPU driver or used to validate a `writeBuffer`/`copyBufferToBuffer` call, resulting in an out-of-bounds GPU (or CPU-side staging buffer) access.
**Escalation**: OOB_WRITE, OOB_READ, HEAP_OVERFLOW, DoS
**5yr frequency**: 6 commits (2021–2026)
**Affected dirs**: `Source/WebGPU/`, `Source/WebCore/html/canvas/`, `Source/WebCore/platform/graphics/angle/`
**Grep anchors**:
```sh
rg "checkedSum|checkedProduct|Checked<" -n Source/WebGPU
rg "indirectOffset|vertexBuffer" -n Source/WebGPU/WebGPU
rg "copyExternalImageToTexture" -n Source/WebGPU
```
**Canonical code**:
```cpp
// ❌ bad — offset + size overflows, passes validation
uint64_t end = offset + size;  // wraps to small value
if (end <= buffer.size())       // passes incorrectly
    doWrite(buffer, offset, size);

// ✅ safe — use Checked<>
Checked<uint64_t, RecordOverflow> end = Checked<uint64_t>(offset) + size;
if (end.hasOverflowed() || end.value() > buffer.size())
    return error;
doWrite(buffer, offset, size);
```
**Exemplar commits**:
- `1a18bdf5a543` — WebGPU vertex buffer validation overflow
- `4f26d9652899` — WebGPU indirectOffset overflow
- `7f49e34b9a17` — copyExternalImageToTexture overflow
- `825c23520355` — RenderBundleEncoder index validation
- `f0359fbb43df` — ANGLE shader type-size overflow

---

### I-UNDERFLOW: Subtraction underflow
**Shape**: A subtraction of unsigned values produces a wrapped-around large value when the subtrahend exceeds the minuend, or a signed subtraction produces a value below the representable range.
**Trigger**: `position - length` where `length > position`, or `buffer_size - access_size` where `access_size > buffer_size`, without a prior guard.
**Sink**: The underflowed value is used as a buffer index (huge positive offset), a loop bound (enormous iteration count), or a length argument to `memcpy`.
**Escalation**: OOB_READ, OOB_WRITE, HEAP_OVERFLOW, DoS
**5yr frequency**: 6 commits (2021–2026)
**Affected dirs**: `Source/WebCore/xml/`, `Source/JavaScriptCore/yarr/`, `Source/JavaScriptCore/wasm/`, `Source/WebCore/platform/`
**Grep anchors**:
```sh
rg "position.*length|size.*offset" -n Source/WebCore/xml/XPathFunctions.cpp
rg "backwardMatch|m_pos" -n Source/JavaScriptCore/yarr
rg "memory_size.*access_size|boundsCheck" -n Source/JavaScriptCore/wasm
```
**Canonical code**:
```cpp
// ❌ bad — subtraction underflows when length > position
unsigned start = position - length;  // wraps to huge value
buffer[start] = value;               // OOB write

// ✅ safe — check before subtracting
if (length > position)
    return;
unsigned start = position - length;
buffer[start] = value;
```
**Exemplar commits**:
- `138f2bcd7d8b` — XPath substring position/length
- `a330a52f59a8` — Yarr backward-match position subtraction
- `c90b978eee24` — Wasm IPInt bounds check memory_size-access_size underflow
- `66bfd48c94bf` — xmlReadMemory integer underflow

---

### I-IMGSIZE: Image/video frame size overflow
**Shape**: Image or video decoding computes frame buffer sizes by multiplying width × height × bytesPerPixel (or similar); the multiplication overflows, leading to a too-small allocation that is then filled with the full decoded frame data.
**Trigger**: A crafted image/video file supplies large dimension values that overflow when multiplied together during decode-time buffer allocation.
**Sink**: The overflowed size is passed to `tryFastCalloc`, `malloc`, or a `Vector` constructor, allocating too little; the subsequent decode writes past the end.
**Escalation**: HEAP_OVERFLOW, OOB_WRITE
**5yr frequency**: 5 commits (2021–2026)
**Affected dirs**: `Source/WebCore/platform/image-decoders/`, `Source/WebCore/platform/graphics/`, `Source/WebKit/`
**Grep anchors**:
```sh
rg "storageSize|frameSizeInBytes|frameBytes" -n Source/WebCore/platform/image-decoders
rg "SharedVideoFrameInfo" -n Source/WebKit
rg "biHeight|INT32_MIN" -n Source/WebCore/platform/image-decoders/bmp
```
**Canonical code**:
```cpp
// ❌ bad — width * height * 4 overflows for large images
size_t bytes = width * height * 4;
auto buffer = tryFastCalloc(1, bytes);  // too small

// ✅ safe — use checked arithmetic
Checked<size_t, RecordOverflow> bytes = Checked<size_t>(width) * height * 4;
if (bytes.hasOverflowed())
    return { };
auto buffer = tryFastCalloc(1, bytes.value());
```
**Exemplar commits**:
- `0ed1220736b8` — image frame size in bytes overflow
- `46ea28d67283` — SharedVideoFrameInfo::storageSize overflow
- `3a311fd2cd7e` — BMP biHeight INT32_MIN negation
- `c031542a9d50` — I420ToNV12 buffer length

---

### I-WASM: Wasm arithmetic overflow
**Shape**: WebAssembly runtime or compiler code performs integer arithmetic on Wasm-level values (memory offsets, array sizes, element counts) that overflows the host machine's integer width, bypassing bounds checks or producing incorrect code.
**Trigger**: A Wasm module supplies large 64-bit offsets (Memory64), large array sizes (GC proposal), or element counts that overflow when multiplied by element size during allocation or bounds checking.
**Sink**: The overflowed value passes a bounds check and is used as a memory access offset, or an allocation uses the truncated size.
**Escalation**: OOB_READ, OOB_WRITE, HEAP_OVERFLOW
**5yr frequency**: 5 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/wasm/`, `Source/JavaScriptCore/wasm/js/`
**Grep anchors**:
```sh
rg "WasmBoundsCheck|BoundsCheck" -n Source/JavaScriptCore/wasm
rg "JSWebAssemblyArray|arrayNew" -n Source/JavaScriptCore/wasm/js
rg "operationIterateResults" -n Source/JavaScriptCore/wasm
```
**Canonical code**:
```cpp
// ❌ bad — element count * element size overflows 32 bits
uint32_t allocSize = elementCount * elementSize;  // overflow
auto* array = tryAllocate(allocSize);

// ✅ safe — use 64-bit or Checked arithmetic
Checked<size_t, RecordOverflow> allocSize =
    Checked<size_t>(elementCount) * elementSize;
if (allocSize.hasOverflowed())
    return nullptr;
auto* array = tryAllocate(allocSize.value());
```
**Exemplar commits**:
- `008ce40466bc` — OMG WasmBoundsCheck Int64 guard
- `9cee5daeabd1` — arrayInitData element vs byte size
- `4b568b921b7a` — JSWebAssemblyArray alloc size 32-bit overflow
- `e03b456698ea` — operationIterateResults i32 truncation

---

### I-IPC: IPC message size overflow
**Shape**: An IPC message handler computes a buffer size or validates message dimensions using arithmetic that can overflow, allowing an oversized or malformed message to bypass validation.
**Trigger**: A compromised or fuzzing-generated IPC message supplies large dimension values; the receiver multiplies or adds them to compute an allocation size or validation bound, and the result overflows.
**Sink**: The overflowed size is used to allocate a too-small buffer that the message payload then overflows, or a validation check passes incorrectly.
**Escalation**: HEAP_OVERFLOW, OOB_WRITE, DoS
**5yr frequency**: 4 commits (2021–2026)
**Affected dirs**: `Source/WebKit/Platform/IPC/cocoa/`, `Source/WebKit/UIProcess/ios/`, `Source/WebCore/platform/graphics/filters/`
**Grep anchors**:
```sh
rg "msgh_size|readFromMachPort" -n Source/WebKit/Platform/IPC
rg "DocumentEditingContext" -n Source/WebKit/UIProcess/ios
rg "kernelSize|feConvolveMatrix" -n Source/WebCore/platform/graphics/filters
```
**Canonical code**:
```cpp
// ❌ bad — msgh_size overflow not checked
size_t bodySize = header->msgh_size - sizeof(mach_msg_header_t);
memcpy(dst, body, bodySize);  // underflow if msgh_size < header size

// ✅ safe — validate before subtraction
if (header->msgh_size < sizeof(mach_msg_header_t))
    return;
size_t bodySize = header->msgh_size - sizeof(mach_msg_header_t);
memcpy(dst, body, bodySize);
```
**Exemplar commits**:
- `15455dbecd5e` — ConnectionCocoa readFromMachPort msgh_size overflow
- `6a616251c48f` — DocumentEditingContext::Range overflow validation
- `97d27fbddaca` — feConvolveMatrix kernelSize area() overflow via IPC

---

### I-TEMPORAL: Temporal/Date arithmetic overflow
**Shape**: Arithmetic on date/time values (epoch milliseconds, duration calculations, calendar conversions) overflows the integer or floating-point representation.
**Trigger**: Multiplying or dividing large timestamp values, computing durations between extreme dates, or converting between time units with large multipliers (ms → ns).
**Sink**: The overflowed value produces incorrect time comparisons, infinite loops in date iteration, or (rarely) is used as an allocation size.
**Escalation**: DoS, INT_OVERFLOW_TO_OOB (rare)
**5yr frequency**: 3 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/runtime/`, `Source/WTF/wtf/`
**Grep anchors**:
```sh
rg "Decimal::operator|temporalDuration" -n Source/JavaScriptCore/runtime
rg "MonotonicallyIncreasingTime|WallTime" -n Source/WTF/wtf
```
**Canonical code**:
```cpp
// ❌ bad — uint64 division intermediate overflows
Decimal operator/(const Decimal& lhs, const Decimal& rhs) {
    uint64_t result = lhs.coefficient() * scaleMultiplier;  // overflow
    return result / rhs.coefficient();
}

// ✅ safe — use wider intermediate or checked arithmetic
Decimal operator/(const Decimal& lhs, const Decimal& rhs) {
    auto result = static_cast<__uint128_t>(lhs.coefficient()) * scaleMultiplier;
    return static_cast<uint64_t>(result / rhs.coefficient());
}
```
**Exemplar commits**:
- `d16c8e20b19e` — Decimal::operator/ uint64 overflow

---

### I-ALLOC: Allocation size overflow
**Shape**: An allocation size is computed by multiplying or adding attacker-influenced values; the arithmetic overflows, causing a too-small allocation that is subsequently filled with more data than it can hold.
**Trigger**: `count * elementSize` or `baseSize + variableSize` overflows, wrapping to a small value that passes to `malloc`, `tryAllocate`, or a `Vector` constructor.
**Sink**: The too-small allocation is written past its end during initialization or copy.
**Escalation**: HEAP_OVERFLOW, OOB_WRITE
**5yr frequency**: 3 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/heap/`, `Source/JavaScriptCore/b3/air/`, `Source/WTF/wtf/`
**Grep anchors**:
```sh
rg "tryAllocateSlow|allocateNonVirtual" -n Source/JavaScriptCore/heap
rg "use\(\)\.count\(\)|def\(\)\.count\(\)" -n Source/JavaScriptCore/b3/air
rg "Deque.*capacity|expandCapacity" -n Source/WTF/wtf
```
**Canonical code**:
```cpp
// ❌ bad — count * size overflows on 32-bit
unsigned allocSize = count * sizeof(Element);  // overflow
void* mem = tryAllocate(allocSize);            // too small

// ✅ safe — checked multiplication
Checked<size_t, RecordOverflow> allocSize =
    Checked<size_t>(count) * sizeof(Element);
if (allocSize.hasOverflowed())
    return nullptr;
void* mem = tryAllocate(allocSize.value());
```
**Exemplar commits**:
- `47b01a388dd8` — CompleteSubspace::tryAllocateSlow 32-bit overflow
- `59f3afb044ea` — GreedyRegAlloc use/def count overflow
- `7e3461d08115` — Deque truncates size_t to unsigned

---

### I-STRING: String length overflow
**Shape**: A string length or capacity calculation overflows, causing a too-small buffer allocation for string data or an incorrect bounds check on string operations.
**Trigger**: Repeated string concatenation, `replace()` that expands the string, or key-length computation for database keys — where the resulting length exceeds `UINT32_MAX` or the maximum representable `String::length()`.
**Sink**: The overflowed length is used to allocate a buffer that is then filled with the full string content, or a bounds check passes incorrectly.
**Escalation**: HEAP_OVERFLOW, OOB_WRITE, DoS
**5yr frequency**: 2 commits (2021–2026)
**Affected dirs**: `Source/WTF/wtf/text/`, `Source/WebCore/Modules/indexeddb/`
**Grep anchors**:
```sh
rg "RecordOverflow|StringBuilder" -n Source/WTF/wtf/text/StringBuilder.cpp
rg "IDBKey.*string|keyLength" -n Source/WebCore/Modules/indexeddb
```
**Canonical code**:
```cpp
// ❌ bad — replacement expands string beyond capacity tracking
void stringReplace(StringBuilder& builder, ...) {
    // repeated appends without overflow check on total length
    builder.append(replacement);  // length wraps
}

// ✅ safe — StringBuilder with RecordOverflow
StringBuilder builder;
builder.append(replacement);
if (builder.hasOverflowed())
    return { };
```
**Exemplar commits**:
- `48e051485568` — StringBuilder RecordOverflow in stringReplace
- `e5eb16d1eda3` — IDB string key length overflow

---

### I-XML: XML/XPath arithmetic overflow
**Shape**: XPath or XML processing functions perform arithmetic on position/length values derived from document content; the arithmetic overflows or underflows, producing incorrect substring bounds.
**Trigger**: XPath `substring()` function receives extreme position or length arguments that overflow when converted to integer indices.
**Sink**: The overflowed indices are used to compute string slice boundaries, causing out-of-bounds reads or incorrect results.
**Escalation**: OOB_READ, DoS
**5yr frequency**: 1 commit (2021–2026)
**Affected dirs**: `Source/WebCore/xml/`
**Grep anchors**:
```sh
rg "FunSubstring|substring" -n Source/WebCore/xml/XPathFunctions.cpp
rg "xmlReadMemory" -n Source/WebCore/xml
```
**Canonical code**:
```cpp
// ❌ bad — position/length overflow in XPath substring
double pos = args[0]->evaluate().toNumber();
double len = args[1]->evaluate().toNumber();
int start = static_cast<int>(pos);  // overflow for extreme values

// ✅ safe — clamp or validate before cast
double pos = args[0]->evaluate().toNumber();
if (!std::isfinite(pos))
    return emptyString();
int start = clampTo<int>(pos);
```
**Exemplar commits**:
- `138f2bcd7d8b` — XPath substring position/length overflow/underflow

---

## Adding new exemplars

When a new integer-overflow fix is committed to WebKit:

1. **Classify** — read the diff and determine which pattern (I-CSS through I-XML) it matches.
   If it matches none, consider whether it represents a new pattern worth adding.
2. **Append** — add the commit hash and a 1-line description to the pattern's
   `Exemplar commits` list.
3. **Update the count** — increment the pattern's `5yr frequency` and the summary
   table count.
4. **Cross-check** — if the commit touches a directory not yet listed in
   `Affected dirs`, add it.

Patterns are intentionally coarse-grained (14 buckets for 128 commits). Resist
the urge to split a pattern unless the new sub-pattern has ≥ 3 exemplars with a
structurally distinct shape.
