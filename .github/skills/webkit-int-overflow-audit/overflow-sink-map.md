# WebKit Integer Overflow → Sink Map

Maps arithmetic overflow sites to their downstream sinks and the bug class
produced. Use to classify severity and determine the fix pattern when an
overflow is found.

---

## 1 · Image decoder

| Field | Detail |
|-------|--------|
| **Arithmetic** | `width * height * bytesPerPixel` |
| **Sink** | `tryAllocate(totalBytes)` / `fastMalloc(totalBytes)` |
| **Bug class** | HEAP_OVERFLOW — undersized buffer, decoder writes full pixel data |
| **Fix pattern** | `checkedProduct<size_t>(width, height, bpp)` → fail if `std::nullopt` |
| **Grep anchors** | `tryAllocate`, `width * height`, `bytesPerPixel`, `ImageDecoder`, `setSize` |

**Example (vulnerable):**

```cpp
size_t bytes = width * height * 4;   // int × int × int → 32-bit overflow
auto buffer = tryAllocate(bytes);    // allocates tiny buffer
// decoder writes width*height*4 actual bytes → heap overflow
```

**Example (fixed):**

```cpp
auto bytes = checkedProduct<size_t>(width, height, bytesPerPixel);
if (!bytes)
    return { };
auto buffer = tryAllocate(*bytes);
```

---

## 2 · WebGL / WebGPU

| Field | Detail |
|-------|--------|
| **Arithmetic** | `elementCount * bytesPerElement` or `width * height * 4` |
| **Sink** | `GPUBuffer::create(size)`, `gl::bufferData(target, size, data, usage)` |
| **Bug class** | OOB_WRITE into GPU-mapped memory; may corrupt GPU heap or leak cross-origin textures |
| **Fix pattern** | `Checked<size_t>` for all buffer-size math; clamp dimensions to implementation limits before multiply |
| **Grep anchors** | `GPUBuffer::create`, `bufferData`, `bufferSubData`, `texImage2D`, `WebGLRenderingContext` |

**Example (vulnerable):**

```cpp
uint32_t size = count * bytesPerElement;   // 32-bit overflow
gl::bufferData(target, size, data, usage); // GPU writes past allocation
```

---

## 3 · Wasm memory

| Field | Detail |
|-------|--------|
| **Arithmetic** | `pages * 65536` (memory.grow) or `len` in `memory.copy(dst, src, len)` |
| **Sink** | `Wasm::Memory::grow(pages)`, `memcpy(base + dst, base + src, len)` |
| **Bug class** | OOB_WRITE — write past Wasm linear memory into adjacent heap objects |
| **Fix pattern** | Bounds-check `dst + len` and `src + len` with `checkedSum`; validate page count ≤ `Memory::maxPageCount` |
| **Grep anchors** | `Memory::grow`, `memory.copy`, `memory.fill`, `Wasm::Instance`, `boundsCheck` |

**Example (vulnerable):**

```cpp
size_t end = offset + length;    // wraps to small value
if (end <= memorySize)           // check passes
    memcpy(base + offset, src, length);  // OOB write
```

**Example (fixed):**

```cpp
auto end = checkedSum<size_t>(offset, length);
if (!end || *end > memorySize)
    return throwRangeError(...);
memcpy(base + offset, src, length);
```

---

## 4 · IPC (Decoder)

| Field | Detail |
|-------|--------|
| **Arithmetic** | `count * elementSize` or `offset + length` in deserialization |
| **Sink** | `Decoder::bufferIsLargeEnoughToContain(size)`, `Decoder::decode(T&)` |
| **Bug class** | OOB_READ of IPC shared-memory buffer → info leak or crash; may chain to OOB_WRITE if decoded data controls a subsequent allocation |
| **Fix pattern** | `checkedProduct<size_t>(count, sizeof(Element))` before `bufferIsLargeEnoughToContain`; reject on overflow |
| **Grep anchors** | `bufferIsLargeEnoughToContain`, `Decoder::decode`, `IPC::Decoder`, `decodeArrayLength` |

**Example (vulnerable):**

```cpp
uint64_t count;
decoder >> count;
size_t bytes = count * sizeof(Element);  // overflow if count is huge
if (!decoder.bufferIsLargeEnoughToContain(bytes))
    return false;
// reads past end of IPC buffer
```

---

## 5 · CSS / Layout

| Field | Detail |
|-------|--------|
| **Arithmetic** | `LayoutUnit(intValue)` — saturating fixed-point (typically 6 fractional bits) |
| **Sink** | Layout tree computations (`RenderBox::setWidth`, `RenderBox::setHeight`) |
| **Bug class** | Rendering glitch — usually NOT memory-safety. `LayoutUnit` saturates at `intMinForLayoutUnit` / `intMaxForLayoutUnit` so values clip rather than wrap |
| **Fix pattern** | Clamp input values to `LayoutUnit` range before construction; check for `LayoutUnit::max()` / `LayoutUnit::min()` saturation |
| **Grep anchors** | `LayoutUnit`, `intMaxForLayoutUnit`, `intMinForLayoutUnit`, `saturatedAddition`, `RenderBox` |

> **Severity note:** Layout overflows rarely produce memory corruption because
> `LayoutUnit` saturates. Flag only if the overflowed value reaches an
> allocation or index that *does not* use `LayoutUnit`.

---

## 6 · String (StringImpl)

| Field | Detail |
|-------|--------|
| **Arithmetic** | `length * 2` (for 16-bit strings) or `length + otherLength` (concatenation) |
| **Sink** | `StringImpl::createUninitialized(length)`, `StringImpl::create(chars, length)` |
| **Bug class** | HEAP_OVERFLOW — undersized string buffer, copy writes full content past end |
| **Fix pattern** | `StringImpl::MaxLength` guards (`RELEASE_ASSERT(length <= MaxLength)`); use `tryCreateUninitialized` for untrusted lengths; `checkedSum` for concatenation lengths |
| **Grep anchors** | `createUninitialized`, `tryCreateUninitialized`, `StringImpl::create`, `MaxLength`, `reallocateInternal` |

**Example (vulnerable):**

```cpp
unsigned newLen = existingLen + appendLen;  // 32-bit wrap
auto impl = StringImpl::createUninitialized(newLen, buf);
memcpy(buf, existingData, existingLen);
memcpy(buf + existingLen, appendData, appendLen);  // writes past allocation
```

---

## 7 · Font (table parsing)

| Field | Detail |
|-------|--------|
| **Arithmetic** | `glyphCount * metricsSize` or `numTables * tableRecordSize` |
| **Sink** | Pointer arithmetic into memory-mapped font data; `tryAllocate(totalSize)` for glyph caches |
| **Bug class** | HEAP_OVERFLOW or OOB_READ — undersized cache allocation; out-of-bounds read of font file buffer |
| **Fix pattern** | `checkedProduct<size_t>(count, recordSize)` before allocation; validate all offsets/counts against actual file size |
| **Grep anchors** | `glyphCount`, `numGlyphs`, `OpenType`, `SFNT`, `FontFace`, `parseCmap`, `parseHead` |

**Example (vulnerable):**

```cpp
uint16_t glyphCount = readU16(data);
size_t tableSize = glyphCount * sizeof(GlyphMetrics);  // 16-bit × constant OK, but...
// ... if glyphCount is read from untrusted font file and metrics struct is large
auto cache = tryAllocate(tableSize);
for (uint16_t i = 0; i < glyphCount; i++)
    readGlyphMetrics(data, i, cache);  // reads past font data if offset unchecked
```

---

## 8 · Audio (buffer allocation)

| Field | Detail |
|-------|--------|
| **Arithmetic** | `frameCount * numberOfChannels * sizeof(float)` |
| **Sink** | `AudioBuffer::create(channels, frames, sampleRate)`, `tryAllocate(totalBytes)` |
| **Bug class** | HEAP_OVERFLOW — undersized audio buffer, rendering writes full frame data |
| **Fix pattern** | `checkedProduct<size_t>(frameCount, channels, sizeof(float))` → reject on overflow; clamp `frameCount` to platform maximum |
| **Grep anchors** | `AudioBuffer::create`, `frameCount`, `numberOfChannels`, `sampleRate`, `AudioArray`, `allocate` |

**Example (vulnerable):**

```cpp
uint32_t frames = jsArgs.frameCount;    // from JS
uint32_t channels = jsArgs.channels;    // from JS
size_t bytes = frames * channels * sizeof(float);  // 32-bit overflow possible
auto buffer = tryAllocate(bytes);
// render loop writes frames * channels * 4 actual bytes → overflow
```

**Example (fixed):**

```cpp
auto bytes = checkedProduct<size_t>(frameCount, numberOfChannels, sizeof(float));
if (!bytes)
    return Exception { RangeError, "Buffer too large"_s };
auto buffer = tryAllocate(*bytes);
```

---

## 9 · Canvas (backing store)

| Field | Detail |
|-------|--------|
| **Arithmetic** | `deviceWidth * deviceHeight * 4` (RGBA backing store) |
| **Sink** | `ImageBuffer::create(size, scale)`, `tryFastCalloc(totalBytes, 1)` |
| **Bug class** | HEAP_OVERFLOW — undersized pixel buffer; `putImageData` / drawing ops write past end |
| **Fix pattern** | `checkedProduct<size_t>(deviceWidth, deviceHeight, 4)` or use `ImageBuffer::create` which internally validates; enforce `maxCanvasArea` limits |
| **Grep anchors** | `ImageBuffer::create`, `createImageBuffer`, `putImageData`, `getImageData`, `HTMLCanvasElement`, `OffscreenCanvas`, `maxCanvasArea` |

**Example (vulnerable):**

```cpp
unsigned devW = cssWidth * deviceScale;   // may overflow if scale > 1
unsigned devH = cssHeight * deviceScale;
size_t bytes = devW * devH * 4;           // 32-bit overflow → tiny alloc
auto buffer = tryFastCalloc(bytes, 1);
// canvas draw fills devW * devH * 4 actual bytes → heap overflow
```

**Example (fixed):**

```cpp
Checked<size_t> devW = static_cast<size_t>(cssWidth) * deviceScale;
Checked<size_t> devH = static_cast<size_t>(cssHeight) * deviceScale;
Checked<size_t> bytes = devW * devH * 4;
if (bytes.hasOverflowed())
    return { };
auto buffer = tryFastCalloc(bytes.value(), 1);
```

---

## Quick-reference summary

| # | Component | Arithmetic | Sink | Bug class | Fix |
|---|-----------|-----------|------|-----------|-----|
| 1 | Image decoder | `w * h * bpp` | `tryAllocate` | HEAP_OVERFLOW | `checkedProduct` |
| 2 | WebGL/WebGPU | `count * elemSize` | `GPUBuffer::create` | OOB_WRITE (GPU) | `Checked<size_t>` |
| 3 | Wasm | `pages * 64K`, `dst + len` | `Memory::grow`, `memcpy` | OOB_WRITE | `checkedSum` + bounds |
| 4 | IPC | `count * sizeof(T)` | `bufferIsLargeEnoughToContain` | OOB_READ | `checkedProduct` |
| 5 | CSS/Layout | `LayoutUnit(val)` | layout tree | Rendering glitch | Clamp (usually safe) |
| 6 | String | `len * 2`, `a + b` | `createUninitialized` | HEAP_OVERFLOW | `MaxLength` guard |
| 7 | Font | `glyphs * metricsSz` | font parse buffer | HEAP_OVERFLOW / OOB_READ | `checkedProduct` + file-size validate |
| 8 | Audio | `frames * ch * sizeof` | `AudioBuffer::create` | HEAP_OVERFLOW | `checkedProduct` |
| 9 | Canvas | `devW * devH * 4` | `ImageBuffer::create` | HEAP_OVERFLOW | `checkedProduct` + area limit |
