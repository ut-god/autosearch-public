# WebKit Bounds-Check Pattern Catalog

> **Methodology**: Bottom-up classification of 684 bounds-related commits across WebKit
> (2021-01-01 → 2026-05-31). Each commit was tagged by keyword and diff-level
> structural analysis, then merged into deduplicated pattern buckets. The result
> is a taxonomy of **17 recurring OOB shapes** that account for the 250
> classified commits. This catalog replaces the earlier individual-CVE listing
> with a structural approach: audit for *patterns*, not individual bugs.

---

## Summary table

| ID | Pattern | 5yr Count |
|----|---------|:---------:|
| B-STACK | Stack overflow / recursion exhaustion | 49 |
| B-GPU | GPU/WebGL/WebGPU buffer overflow | 34 |
| B-WASM | Wasm memory bounds check | 27 |
| B-JSBUFFER | JS buffer/typed array OOB | 25 |
| B-CODEC | Image/media codec overflow | 23 |
| B-STRING | String/StringView bounds | 18 |
| B-SHARED | SharedBuffer/SharedMemory OOB | 11 |
| B-INTOVF | Integer overflow to OOB | 10 |
| B-REGEX | Regex engine bounds | 9 |
| B-CSS | CSS/font/layout bounds | 8 |
| B-RACE | Race-to-OOB (TOCTOU on size) | 7 |
| B-TRUNC | Truncation/narrowing to OOB | 7 |
| B-OFFBY1 | Off-by-one | 6 |
| B-VECTOR | Vector/span invalidation | 5 |
| B-MEMCPY | Sized memory copy overflow | 5 |
| B-DISPLAY | Display list / GPU process OOB | 3 |
| B-IPC | IPC decode/encode overflow | 3 |

---

## Pattern entries

---

### B-STACK: Stack overflow / recursion exhaustion
**Shape**: Unbounded recursion (or deep nesting) in a parser, tree walker, or layout engine exhausts the native call stack before any depth guard fires.
**Trigger**: Deeply nested or self-referential input (CSS, HTML, JSON, WGSL, accessibility tree) drives recursive descent without a depth counter or with a bypassable one.
**Sink**: The native stack overflows, corrupting adjacent stack frames or triggering a controlled crash.
**Escalation**: stack overflow, DoS, potential RCE if stack canary is bypassed.
**5yr frequency**: 49 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/runtime/`, `Source/WebCore/css/parser/`, `Source/WebCore/html/parser/`, `Source/WebCore/accessibility/`, `Source/WebGPU/WGSL/`
**Grep anchors**:
```sh
rg "stackOverflow|StackCheck|recursion" -n Source/JavaScriptCore/runtime Source/WebCore/css/parser
rg "m_treeDepth|maxDepth|kMaxRecursionDepth" -n Source/WebCore/html/parser Source/WebGPU/WGSL
```
**Canonical code**:
```cpp
// ❌ bad — no depth guard on recursive descent
void parseExpression() {
    parseExpression();  // unbounded recursion
}

// ✅ safe — depth counter with early return
void parseExpression(unsigned depth = 0) {
    if (depth > maxAllowedDepth)
        return;
    parseExpression(depth + 1);
}
```
**Exemplar commits**:
- `06f13ed8ff16` (2023) — JSON LiteralParser stack overflow
- `1cb22d29f824` (2023) — focus navigation recursive shadow hosts
- `3c94670d1f14` (2023) — CSS revert eternal recursion
- `496ec1f2f2f8` (2024) — WGSL parser recursion bypass
- `915b2088b808` (2023) — deep div nesting HTML parser
- `e22f4427f1ee` (2023) — recursive AX tree traversal
- `e37feef37670` (2024) — CSSParser large stack-allocated vector
- `57bce4e89635` (2024) — CSS revert-layer 64k recursion

---

### B-GPU: GPU/WebGL/WebGPU buffer overflow
**Shape**: A GPU-side buffer operation (vertex, index, uniform, storage, texture) uses an unchecked or stale size/offset, writing or reading past the buffer's allocated region.
**Trigger**: Missing or incorrect validation of buffer offsets, sizes, bind-group layouts, or vertex attribute strides in the WebGPU/WebGL/ANGLE pipeline.
**Sink**: The GPU process performs an out-of-bounds read or write on GPU-shared memory or a mapped buffer.
**Escalation**: OOB read, OOB write, GPU process compromise, info-leak.
**5yr frequency**: 34 commits (2021–2026)
**Affected dirs**: `Source/WebGPU/WebGPU/`, `Source/WebGPU/WGSL/`, `Source/WebCore/Modules/WebGPU/`, `Source/ThirdParty/ANGLE/`
**Grep anchors**:
```sh
rg "validateBufferUsage|maxBufferSize|m_size" -n Source/WebGPU/WebGPU
rg "createBindGroup|vertexBuffer|indexBuffer" -n Source/WebGPU/WebGPU
rg "writeBuffer|copyBufferToBuffer" -n Source/WebGPU/WebGPU
```
**Canonical code**:
```cpp
// ❌ bad — stale m_size used after buffer resize
void writeBuffer(uint64_t offset, auto* data, uint64_t size) {
    memcpy(m_buffer + offset, data, size);  // m_size not revalidated
}

// ✅ safe — revalidate current buffer size
void writeBuffer(uint64_t offset, auto* data, uint64_t size) {
    if (offset + size > m_buffer.currentSize())
        return;
    memcpy(m_buffer + offset, data, size);
}
```
**Exemplar commits**:
- `0fa174e18a82` (2024) — RemoteBuffer::copy wrong size
- `0fcfda2cd76d` (2024) — createBindGroup shaderStage OOB
- `15ddef0e0842` (2024) — flipped comparison vertex buffer OOB
- `199e7c1a1ed8` (2024) — RenderPassEncoder bounds check
- `4a8e3ed33b45` (2024) — WGSL unsized array no bounds
- `7fed8609a814` (2024) — writeBuffer stale m_size
- `69d662308353` (2023) — ANGLE Metal restart-index OOB
- `e87abc019b58` (2024) — multidimensional texture write OOB
- `ff9bb65302c8` (2024) — index buffer shared between render bundles

---

### B-WASM: Wasm memory bounds check
**Shape**: A WebAssembly operation accesses memory, a table, or an array without proper bounds checking, or the bounds-check logic itself is incorrect (e.g., wrong size unit, uninitialized register, disabled path).
**Trigger**: A Wasm instruction (load/store, array access, ref.call, memory.grow) bypasses or uses an incorrect bounds check in the BBQ/OMG JIT or the interpreter.
**Sink**: The Wasm instance reads or writes past its linear memory, table, or GC-managed array.
**Escalation**: OOB read, OOB write, arbitrary R/W, sandbox escape.
**5yr frequency**: 27 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/wasm/`, `Source/JavaScriptCore/b3/`, `Source/JavaScriptCore/jit/`
**Grep anchors**:
```sh
rg "boundsCheck|m_boundsCheckingSize" -n Source/JavaScriptCore/wasm
rg "Memory64|BBQ" -n Source/JavaScriptCore/wasm
rg "arrayNew\|arrayGet\|arraySet" -n Source/JavaScriptCore/wasm
```
**Canonical code**:
```cpp
// ❌ bad — element count used where byte count required
void arrayInitData(uint32_t dstIndex, uint32_t srcOffset, uint32_t count) {
    memcpy(array + dstIndex, data + srcOffset, count);  // count is elements, not bytes
}

// ✅ safe — convert to byte size
void arrayInitData(uint32_t dstIndex, uint32_t srcOffset, uint32_t count) {
    auto byteCount = checkedProduct(count, elementSize);
    if (byteCount.hasOverflowed() || srcOffset + byteCount > dataSize)
        return trap();
    memcpy(array + dstIndex * elementSize, data + srcOffset, byteCount);
}
```
**Exemplar commits**:
- `12ee76dafdbd` (2024) — BBQ missing GC array alloc size check
- `653249798501` (2024) — Memory64 BBQ bounds disabled
- `9cee5daeabd1` (2024) — arrayInitData element vs byte size
- `c827e066953d` (2024) — ref.call function index unchecked
- `cb7f341491b7` (2024) — i31ref wrong size OOB stack read
- `d8a913bd3feb` (2024) — Memory64 BBQ incorrect bounds
- `dde2af69c897` (2024) — bounds-checking-size register uninitialized
- `e0954318753d` (2024) — BBQ OSR uninitialized frame stack overflow

---

### B-JSBUFFER: JS buffer/typed array OOB
**Shape**: A JavaScript fast-path operation on an ArrayBuffer, TypedArray, or internal Vector uses an index or length that has become stale due to a mid-operation callback, detach, or resize.
**Trigger**: A JS-observable callback (species constructor, Symbol.toPrimitive, getter) fires during a bulk array operation, resizing or detaching the buffer while the C++ fast path still holds the old length.
**Sink**: The fast path writes or reads past the (now-smaller or detached) buffer using the cached length.
**Escalation**: heap overflow, OOB read, OOB write, arbitrary R/W.
**5yr frequency**: 25 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/runtime/`, `Source/WebCore/Modules/webaudio/`, `Source/WebCore/Modules/encryptedmedia/`
**Grep anchors**:
```sh
rg "fastFill|fastCopy|fillFast" -n Source/JavaScriptCore/runtime
rg "m_length|m_vector|butterfly" -n Source/JavaScriptCore/runtime/JSArray
rg "AudioWorkletProcessor" -n Source/WebCore/Modules/webaudio
```
**Canonical code**:
```cpp
// ❌ bad — cached length used after user callback may have resized
auto length = array->length();
callUserCode();  // may resize/detach array
for (unsigned i = 0; i < length; i++)
    array->setIndex(i, value);  // OOB if length shrank

// ✅ safe — recheck length after callback
callUserCode();
auto length = array->length();
if (array->isDetached())
    return;
for (unsigned i = 0; i < length; i++)
    array->setIndex(i, value);
```
**Exemplar commits**:
- `c702978087bc` (2024) — Array fast fill OOB from mid-op length change
- `7d56f3cb6796` (2024) — AudioWorkletProcessor missing exception check OOB
- `da81bcac35cf` (2024) — m_keyStatuses vector OOB index

---

### B-CODEC: Image/media codec overflow
**Shape**: An image decoder, video encoder/decoder, or media pipeline operation uses unchecked frame dimensions, buffer sizes, or codec parameters, leading to an overflowed allocation or a copy past buffer bounds.
**Trigger**: Malformed or adversarial media input (VP9, AV1, I420, NV12, VideoFrame) provides dimensions, offsets, or layer counts that are not validated before buffer allocation or copy.
**Sink**: A `memcpy`, NEON/SSE intrinsic, or codec-internal buffer write overflows the allocated region.
**Escalation**: heap overflow, stack overflow, OOB read, OOB write, DoS.
**5yr frequency**: 23 commits (2021–2026)
**Affected dirs**: `Source/WebCore/Modules/webcodecs/`, `Source/ThirdParty/libwebrtc/`, `Source/WebCore/platform/mediastream/`, `Source/ThirdParty/libaom/`
**Grep anchors**:
```sh
rg "VideoFrame|createNV12|I420ToNV12" -n Source/WebCore/Modules/webcodecs
rg "num_spatial_layers|aom_codec" -n Source/ThirdParty/libwebrtc
rg "CVPixelBuffer|copyTo" -n Source/WebCore/platform/mediastream
```
**Canonical code**:
```cpp
// ❌ bad — buffer size computed from unvalidated frame dimensions
auto buffer = allocate(width * height * 3 / 2);  // NaN or negative bypass
memcpy(buffer, src, width * height * 3 / 2);

// ✅ safe — validate dimensions and use checked arithmetic
auto bufferSize = checkedProduct(width, height, 3u);
bufferSize /= 2;
if (bufferSize.hasOverflowed() || !isValidDimension(width, height))
    return { };
auto buffer = allocate(bufferSize);
memcpy(buffer, src, bufferSize);
```
**Exemplar commits**:
- `176844ce6b70` (2024) — VideoFrame::createNV12 buffer size
- `15774fae27ec` (2023) — VP9 packetizer stack overflow
- `1b5e5ce3caa0` (2023) — AV1 encoder OOB
- `58f0a3c82680` (2024) — AV1 NEON 8-byte read from 3-byte buf
- `a6f57c1a1ab9` (2023) — libaom aom_scaled_2d_ssse3 stack overflow
- `bb644de42b02` (2023) — VP9 num_spatial_layers
- `c031542a9d50` (2024) — I420ToNV12 buffer length
- `c1787ccc4e91` (2024) — VideoFrame copyTo negative x/y
- `ef46d74db28f` (2024) — VideoFrame NaN bypass
- `ebb91ef51ed3` (2024) — RTCCVPixelBuffer toI420

---

### B-STRING: String/StringView bounds
**Shape**: A string operation (substring, character access, span construction) uses an incorrect length, confuses nul-terminated and counted representations, or iterates with an always-true loop condition.
**Trigger**: Mismatched string length semantics (Span8 vs nul-terminated, `uint8_t` vs `char`), unsigned underflow making a loop condition always true, or reading past a StringView's end.
**Sink**: A character read or memcpy extends past the string's allocated storage.
**Escalation**: OOB read, info-leak, DoS.
**5yr frequency**: 18 commits (2021–2026)
**Affected dirs**: `Source/WTF/wtf/text/`, `Source/WebCore/html/parser/`, `Source/WebCore/platform/`, `Source/WebCore/platform/gstreamer/`
**Grep anchors**:
```sh
rg "Span8|StringView|ASCIILiteral" -n Source/WTF/wtf/text
rg "nul.terminated\|strlen" -n Source/WebCore/platform
rg "TextRun\|HTMLMetaCharsetParser" -n Source/WebCore/html/parser
```
**Canonical code**:
```cpp
// ❌ bad — Span8 from nul-terminated pointer loses length info
auto span = Span8(ptr);  // assumes nul-terminated, but data is counted

// ✅ safe — pass explicit length
auto span = Span8(ptr, knownLength);
```
**Exemplar commits**:
- `26918e6cd63c` (2024) — Span8 vs nul-terminated in Skia/GLib
- `431ee8915736` (2024) — GStreamer SDP uint8_t vs nul-terminated
- `675df538a038` (2024) — size_t loop always ≥0 infinite loop OOB
- `e85dcb7a35a7` (2024) — HTMLMetaCharsetParser past-end
- `abaf97d89d1a` (2024) — keysymModifiersGetMask p<p+size always true
- `b6da11826336` (2024) — ASCIILiteral bounds
- `da6ed35d5041` (2024) — TextRun bounds

---

### B-SHARED: SharedBuffer/SharedMemory OOB
**Shape**: A SharedBuffer, SharedMemory, or mapped data region is accessed with an offset or range that exceeds the actual data size, often because the caller computes a subspan from an HTTP `Range` header or IPC-supplied offset without clamping.
**Trigger**: An externally-supplied range (HTTP Range, IPC offset+length) is applied to a SharedBuffer without checking it fits within the buffer's contiguous region.
**Sink**: A `subspan()`, `data() + offset`, or `createHandle()` produces a view past the buffer's end.
**Escalation**: OOB read, info-leak, DoS.
**5yr frequency**: 11 commits (2021–2026)
**Affected dirs**: `Source/WebCore/platform/`, `Source/WebKit/NetworkProcess/`, `Source/WebKit/Shared/`
**Grep anchors**:
```sh
rg "SharedBuffer|SharedMemory|subspan" -n Source/WebCore/platform
rg "Range.*request\|contentRange" -n Source/WebKit/NetworkProcess
```
**Canonical code**:
```cpp
// ❌ bad — range from HTTP header applied without bounds check
auto sub = buffer->subspan(rangeStart, rangeEnd - rangeStart);  // may exceed buffer

// ✅ safe — clamp to actual buffer size
auto actualSize = buffer->size();
auto clampedEnd = std::min(rangeEnd, actualSize);
if (rangeStart >= clampedEnd)
    return { };
auto sub = buffer->subspan(rangeStart, clampedEnd - rangeStart);
```
**Exemplar commits**:
- `cc89df4bf098` (2024) — Blob URL range request subspan OOB

---

### B-INTOVF: Integer overflow to OOB
**Shape**: An arithmetic operation on sizes, indices, or offsets overflows (wraps around) an integer type, producing a small value that passes a bounds check but leads to an undersized allocation or an OOB access.
**Trigger**: Unchecked addition, multiplication, or subtraction on user-controlled sizes (e.g., `maxGroupIndex + 1` wraps to 0, XML content length underflows, double-to-uint8_t narrows).
**Sink**: The wrapped value is used as a buffer size (undersized allocation) or as an index (OOB access).
**Escalation**: heap overflow, OOB write, arbitrary R/W.
**5yr frequency**: 10 commits (2021–2026)
**Affected dirs**: `Source/WebGPU/WebGPU/`, `Source/WebCore/xml/parser/`, `Source/JavaScriptCore/runtime/`, `Source/WebKit/UIProcess/`
**Grep anchors**:
```sh
rg "checkedSum|checkedProduct|Checked<" -n Source/WebGPU/WebGPU
rg "xmlReadMemory\|xmlParseMemory" -n Source/WebCore/xml/parser
rg "static_cast<uint8_t>" -n Source/JavaScriptCore/runtime
```
**Canonical code**:
```cpp
// ❌ bad — maxGroupIndex + 1 wraps to 0 when maxGroupIndex == UINT32_MAX
uint32_t count = maxGroupIndex + 1;
auto buffer = allocate(count);  // allocates 0 bytes

// ✅ safe — use checked arithmetic
auto count = checkedSum(maxGroupIndex, 1u);
if (count.hasOverflowed())
    return error();
auto buffer = allocate(count);
```
**Exemplar commits**:
- `630efa7ca19e` (2024) — WebGPU maxGroupIndex+1 wraps to 0
- `66bfd48c94bf` (2023) — xmlReadMemory integer underflow
- `ce0c3918570d` (2024) — Temporal daysInMonth double→uint8_t
- `d22d04217d84` (2024) — WPEToplevelWayland wl_array size

---

### B-REGEX: Regex engine bounds
**Shape**: The regular expression engine (YARR) writes past a result buffer during replacement, backreference expansion, or pattern compilation.
**Trigger**: A replacement string or backreference expands to a size larger than the pre-allocated result buffer, and the size estimation is wrong or missing.
**Sink**: A `StringBuffer` or internal scratch buffer overflows during `replace()` or compilation.
**Escalation**: heap overflow, OOB write, arbitrary R/W.
**5yr frequency**: 9 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/yarr/`, `Source/JavaScriptCore/runtime/`
**Grep anchors**:
```sh
rg "StringBuffer|substituteBackreferences|replaceUsingRegExpSearch" -n Source/JavaScriptCore/runtime
rg "YarrPattern|YarrInterpreter" -n Source/JavaScriptCore/yarr
```
**Canonical code**:
```cpp
// ❌ bad — replacement buffer sized for input, not for expanded output
StringBuffer<UChar> buffer(inputLength);
// replacement with backrefs can exceed inputLength
expandReplacement(buffer);  // overflow

// ✅ safe — compute expanded size first
auto expandedSize = computeReplacementSize(input, replacement);
StringBuffer<UChar> buffer(expandedSize);
expandReplacement(buffer);
```
**Exemplar commits**:
- `e3c1c1295f4a` (2024) — StringBuffer overflow in RegExp replace

---

### B-CSS: CSS/font/layout bounds
**Shape**: A CSS property parser, SVG animation interpolator, or font shaping routine accesses an array or list using an index derived from untrusted CSS/SVG values without bounds checking.
**Trigger**: A CSS value list (keyTimes, keyPoints, kernel), font metric, or shadow-blur parameter is zero-length or exceeds the backing array, and the code indexes without checking.
**Sink**: An array subscript or span access goes out of bounds.
**Escalation**: OOB read, OOB write, DoS.
**5yr frequency**: 8 commits (2021–2026)
**Affected dirs**: `Source/WebCore/css/`, `Source/WebCore/rendering/`, `Source/WebCore/svg/`, `Source/WebCore/platform/graphics/`
**Grep anchors**:
```sh
rg "keyTimes|keyPoints|feConvolveMatrix" -n Source/WebCore/svg
rg "ShadowBlur|kernelSize" -n Source/WebCore/platform/graphics
rg "CSSValueList|opticalSizing" -n Source/WebCore/css
```
**Canonical code**:
```cpp
// ❌ bad — zero-length keyTimes list indexed unconditionally
float progress = keyTimes[segmentIndex];  // OOB if keyTimes is empty

// ✅ safe — check list size before indexing
if (segmentIndex >= keyTimes.size())
    return;
float progress = keyTimes[segmentIndex];
```
**Exemplar commits**:
- `1e8c797c8799` (2024) — ShadowBlur precision mismatch
- `2cc9274ac081` (2024) — SVG keyTimes zero OOB
- `3cfb6575ec08` (2024) — feConvolveMatrix kernel OOB
- `53e67f679530` (2024) — SVG keyPoints zero OOB
- `7bc1ae1abbb9` (2024) — ShadowBlur 1px subspan
- `d54f0abea23e` (2024) — CSSValueList bounds
- `e9e9b4699c26` (2024) — font optical sizing OOB

---

### B-RACE: Race-to-OOB (TOCTOU on size)
**Shape**: A buffer size or length is validated on one thread (or at one point in time), but the underlying data is mutated by another thread or callback before the access occurs, producing a time-of-check/time-of-use gap.
**Trigger**: Shared memory, cross-thread buffers, or main-thread/audio-thread shared arrays where the size is read once and the data is accessed later without holding a lock or snapshot.
**Sink**: The access uses the stale (pre-mutation) size, reading or writing past the now-different buffer.
**Escalation**: OOB read, OOB write, heap overflow, arbitrary R/W.
**5yr frequency**: 7 commits (2021–2026)
**Affected dirs**: `Source/WebGPU/WebGPU/`, `Source/WebCore/Modules/webaudio/`, `Source/WebCore/platform/`, `Source/WebKit/Shared/`
**Grep anchors**:
```sh
rg "TOCTOU|shmem|SharedMemory" -n Source/WebGPU/WebGPU
rg "m_formatDescriptions|RemoteQueue" -n Source/WebKit/Shared
rg "AudioWorkletProcessor.*resize" -n Source/WebCore/Modules/webaudio
```
**Canonical code**:
```cpp
// ❌ bad — size read from shared memory, then data read without snapshot
auto size = shmem->header()->size;  // attacker changes size after read
processData(shmem->data(), size);   // OOB

// ✅ safe — snapshot size and data atomically or validate post-copy
auto size = shmem->header()->size;
auto localCopy = copyToLocal(shmem->data(), size);
if (!validateCopy(localCopy, size))
    return;
processData(localCopy, size);
```
**Exemplar commits**:
- `05c71102d9b4` (2024) — Length::ref cross-thread
- `1c283c67a9c0` (2024) — PDF loader span invalidated
- `3aed028b8f7b` (2024) — RemoteBuffer post-validation write
- `48fc66a95fab` (2024) — RemoteQueue shmem TOCTOU
- `5da8d58eb9a7` (2024) — formatDescriptions array mutation
- `9db08685b535` (2024) — duplicate socket IDs
- `a790f14404a5` (2024) — AudioWorkletProcessor resize race

---

### B-TRUNC: Truncation/narrowing to OOB
**Shape**: A wide integer (size_t, uint64_t, double) is narrowed to a smaller type (unsigned, uint8_t) during a size or index computation, silently truncating the value and producing a small number that passes subsequent bounds checks.
**Trigger**: An implicit or explicit narrowing cast (`static_cast<unsigned>(size_t_value)`) discards high bits, causing a large value to appear small.
**Sink**: The truncated value is used as a buffer size (undersized allocation) or loop bound (OOB access).
**Escalation**: heap overflow, OOB write, OOB read.
**5yr frequency**: 7 commits (2021–2026)
**Affected dirs**: `Source/WebCore/platform/text/`, `Source/WTF/wtf/text/`, `Source/JavaScriptCore/runtime/`
**Grep anchors**:
```sh
rg "static_cast<unsigned>|static_cast<uint8_t>" -n Source/WebCore/platform/text
rg "size_t.*unsigned\|narrowing" -n Source/WTF/wtf/text
```
**Canonical code**:
```cpp
// ❌ bad — size_t truncated to unsigned
unsigned len = static_cast<unsigned>(input.length());  // truncates on 64-bit
auto buffer = allocate(len);  // undersized if input.length() > UINT_MAX

// ✅ safe — keep full width or use checked conversion
size_t len = input.length();
if (len > std::numeric_limits<unsigned>::max())
    return error();
auto buffer = allocate(len);
```
**Exemplar commits**:
- `aff0d180af6e` (2024) — TextCodecUTF8 size_t→unsigned truncation

---

### B-OFFBY1: Off-by-one
**Shape**: A bounds check uses `>` instead of `>=` (or vice versa), or an index computation is off by one, allowing exactly one element past the end to be accessed.
**Trigger**: Fencepost error in a comparison (`index > size` should be `index >= size`), or a length computed as `end - start` when it should be `end - start + 1` (or the reverse).
**Sink**: A single-element OOB read or write at the boundary of a buffer or array.
**Escalation**: OOB read, OOB write (1 byte/element), info-leak.
**5yr frequency**: 6 commits (2021–2026)
**Affected dirs**: `Source/WebCore/inspector/`, `Source/JavaScriptCore/`, `Source/WebCore/`
**Grep anchors**:
```sh
rg "nameIndex\s*>" -n Source/WebCore/inspector
rg ">=.*\\.size\\(\\)|> .*\\.size\\(\\)" -n Source/JavaScriptCore
```
**Canonical code**:
```cpp
// ❌ bad — > instead of >=
if (nameIndex > names.size())  // allows nameIndex == names.size()
    return;
auto& name = names[nameIndex];  // OOB by 1

// ✅ safe — >= catches the boundary
if (nameIndex >= names.size())
    return;
auto& name = names[nameIndex];
```
**Exemplar commits**:
- `0fa2a9fb892d` (2024) — source map nameIndex > vs >=

---

### B-VECTOR: Vector/span invalidation
**Shape**: Code holds a span, pointer, or index into a Vector or FixedVector; a concurrent or subsequent operation resizes or replaces the backing store, invalidating the held reference.
**Trigger**: A `mergeSlow`, `append`, or structural mutation on one Vector while another piece of code holds a span or index derived from a different (or the same) Vector's old backing store.
**Sink**: The stale span/pointer dereferences freed or reallocated memory.
**Escalation**: OOB read, OOB write, heap overflow.
**5yr frequency**: 5 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/b3/`, `Source/WTF/wtf/`, `Source/WebCore/`
**Grep anchors**:
```sh
rg "BitVector|mergeSlow|FixedVector" -n Source/WTF/wtf
rg "TrailingArray" -n Source/WTF/wtf
rg "m_vector.*sync\|two.*vector" -n Source/WebCore
```
**Canonical code**:
```cpp
// ❌ bad — mergeSlow indexes other's span which may be smaller
void BitVector::mergeSlow(const BitVector& other) {
    for (size_t i = 0; i < m_size; i++)
        m_bits[i] |= other.m_bits[i];  // other may have fewer words
}

// ✅ safe — clamp to minimum size
void BitVector::mergeSlow(const BitVector& other) {
    auto commonWords = std::min(m_size, other.m_size);
    for (size_t i = 0; i < commonWords; i++)
        m_bits[i] |= other.m_bits[i];
}
```
**Exemplar commits**:
- `3b3138e0af6c` (2024) — BitVector::mergeSlow indexes other's smaller span
- `bd841a095367` (2024) — TrailingArray/FixedVector bounds
- `ee944cef38ab` (2024) — two vectors out of sync

---

### B-MEMCPY: Sized memory copy overflow
**Shape**: A `memcpy`, `memmove`, or manual byte-copy uses a size derived from untrusted input (typically a parsed media container box) without validating it against the source or destination buffer size.
**Trigger**: A media container parser (ISOBMFF) reads a box length from the file and uses it directly as a `memcpy` size, without checking that the source data is at least that large.
**Sink**: The `memcpy` reads past the source buffer or writes past the destination buffer.
**Escalation**: heap overflow, OOB read, info-leak.
**5yr frequency**: 5 commits (2021–2026)
**Affected dirs**: `Source/WebCore/platform/graphics/iso/`, `Source/WebCore/Modules/mediasource/`
**Grep anchors**:
```sh
rg "memcpy|ISOBox|ISOTrackEncryption" -n Source/WebCore/platform/graphics/iso
rg "parseBox|readBox" -n Source/WebCore/platform/graphics/iso
```
**Canonical code**:
```cpp
// ❌ bad — box size used as memcpy length without validation
auto boxSize = readUint32();
memcpy(dst, src, boxSize);  // boxSize may exceed src buffer

// ✅ safe — validate against available data
auto boxSize = readUint32();
if (boxSize > availableBytes())
    return false;
memcpy(dst, src, boxSize);
```
**Exemplar commits**:
- `5c059ab32c26` (2024) — ISOTrackEncryptionBox memcpy
- `9d792587594f` (2024) — ISOFairPlayStreamingKeyRequestInfoBox memcpy
- `c31488496881` (2024) — ISOProtectionSystemSpecificHeaderBox memcpy

---

### B-DISPLAY: Display list / GPU process OOB
**Shape**: The display list serialization/deserialization code reads or writes past item boundaries because item lengths are not validated, or the iterator trusts encoded type/length fields from a compromised renderer process.
**Trigger**: A malformed or attacker-crafted display list item has a type or length field that exceeds the actual buffer, and the GPU-process-side iterator does not validate before reading.
**Sink**: The `DisplayListIterator` reads past the display list buffer, or `ItemHandle::safeCopy` copies beyond item bounds.
**Escalation**: OOB read, GPU process compromise, sandbox escape.
**5yr frequency**: 3 commits (2021–2026)
**Affected dirs**: `Source/WebCore/platform/graphics/displaylists/`
**Grep anchors**:
```sh
rg "DisplayListIterator|ItemHandle|safeCopy" -n Source/WebCore/platform/graphics/displaylists
rg "itemLength|paddedSize" -n Source/WebCore/platform/graphics/displaylists
```
**Canonical code**:
```cpp
// ❌ bad — item length from buffer used without validation
auto length = readItemLength();
auto* item = reinterpret_cast<Item*>(buffer + offset);
memcpy(dst, item, length);  // length may exceed remaining buffer

// ✅ safe — validate item length against remaining buffer
auto length = readItemLength();
if (offset + length > bufferSize)
    return false;
auto* item = reinterpret_cast<Item*>(buffer + offset);
memcpy(dst, item, length);
```
**Exemplar commits**:
- `0f1e82ddd57a` (2024) — display list item length validation
- `617107b2ae1f` (2024) — DisplayListIterator type/length validation
- `adf30e4601db` (2024) — ItemHandle::safeCopy no bounds check

---

### B-IPC: IPC decode/encode overflow
**Shape**: An IPC message encoder or decoder writes or reads past its buffer because `grow`/`reserve` arithmetic overflows, or a decoded type index exceeds the valid variant range.
**Trigger**: A compromised or malformed IPC message contains a size, count, or type index that is not validated before use in buffer arithmetic or `std::variant` construction.
**Sink**: The encoder writes past its buffer, or the decoder constructs an invalid variant / reads past message bounds.
**Escalation**: OOB write, OOB read, type confusion, sandbox escape.
**5yr frequency**: 3 commits (2021–2026)
**Affected dirs**: `Source/WebKit/Platform/IPC/`, `Source/WebKit/Shared/`
**Grep anchors**:
```sh
rg "IPC::Encoder|IPC::Decoder" -n Source/WebKit/Platform/IPC
rg "std::variant.*decode\|variantIndex" -n Source/WebKit/Platform/IPC
rg "grow\|reserve" -n Source/WebKit/Platform/IPC/Encoder
```
**Canonical code**:
```cpp
// ❌ bad — variant type index from IPC not bounds-checked
auto typeIndex = decoder.decode<uint32_t>();
return constructVariant(typeIndex);  // OOB if typeIndex >= variant_size

// ✅ safe — validate type index against variant size
auto typeIndex = decoder.decode<uint32_t>();
if (typeIndex >= std::variant_size_v<VariantType>)
    return std::nullopt;
return constructVariant(typeIndex);
```
**Exemplar commits**:
- `28a9b7ab2497` (2024) — IPC::Encoder grow/reserve bounds
- `79efdcf66cc0` (2024) — std::variant IPC decoding OOB type index

---

## Adding new exemplars

When a new bounds-check fix is committed to WebKit:

1. **Classify** — read the diff and determine which pattern (B-STACK through B-IPC) it matches.
   If it matches none, consider whether it represents a new pattern worth adding.
2. **Append** — add the commit hash and a 1-line description to the pattern's
   `Exemplar commits` list.
3. **Update the count** — increment the pattern's `5yr frequency` and the summary
   table count.
4. **Cross-check** — if the commit touches a directory not yet listed in
   `Affected dirs`, add it.

Patterns are intentionally coarse-grained (17 buckets for 250 commits). Resist
the urge to split a pattern unless the new sub-pattern has ≥ 3 exemplars with a
structurally distinct shape.
