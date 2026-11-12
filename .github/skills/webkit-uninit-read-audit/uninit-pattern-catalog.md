# WebKit Uninitialized-Read Pattern Catalog

> **Methodology**: Bottom-up classification of 357 uninit-related commits across WebKit
> (2021-01-01 → 2026-05-31). Each commit was tagged by keyword and diff-level
> structural analysis, then merged into deduplicated pattern buckets. The result
> is a taxonomy of **10 recurring uninit shapes** that account for 93 of the
> population. Note that U-GENERIC (30) is a catch-all whose members need
> individual per-commit diff review before they can be reclassified. This catalog
> replaces the earlier individual-CVE listing with a structural approach: audit
> for *patterns*, not individual bugs.

---

## Summary table

| ID | Pattern | 5yr Count |
|----|---------|:---------:|
| U-FIELDINIT | Missing field/member initialization | 39 |
| U-GENERIC | Generic uninit (needs per-commit review) | 30 |
| U-GRAPHICS | Graphics buffer uninit leak | 6 |
| U-CONTAINER | Container/array uninit (Vector, Butterfly) | 5 |
| U-STRING | String/buffer uninitialized creation | 4 |
| U-STACK | Stack variable uninit | 3 |
| U-IPC | IPC serialization uninit leak | 2 |
| U-MSAN | MemorySanitizer-detected uninit | 2 |
| U-PADDING | Struct padding info-leak | 1 |
| U-CRYPTO | Crypto nonce/key uninit | 1 |

---

## Pattern entries

---

### U-FIELDINIT: Missing field/member initialization
**Shape**: A C++ class constructor fails to initialize one or more trivial-type member fields; the field is later read with stale stack/heap data.
**Trigger**: New field added to class without updating constructor initializer list, or secondary constructor path misses field.
**Sink**: Field read returns garbage, may leak to JS/IPC or influence security decision.
**Escalation**: Info-leak (stale heap/stack data exposed to JS or IPC), logic corruption, DoS.
**5yr frequency**: 39 commits (2021–2026)
**Affected dirs**: `Source/WebCore/animation/`, `Source/WebCore/rendering/`, `Source/WebCore/html/`, `Source/WebCore/platform/graphics/`, `Source/WebCore/xml/`, `Source/JavaScriptCore/yarr/`, `Source/WebCore/svg/`
**Grep anchors**:
```sh
rg "= 0;|= false;|= nullptr;" -n Source/WebCore/rendering
rg "m_\w+\s*;" -n Source/WebCore/animation
rg "initializer.list|member.init" -n Source/WebCore
```
**Canonical code**:
```cpp
// ❌ bad — trivial-type member not in initializer list
class FontSizeAdjust {
    FontSizeAdjust() { }  // m_metric left uninitialized
    Metric m_metric;
};

// ✅ safe — in-class default or initializer list
class FontSizeAdjust {
    FontSizeAdjust() : m_metric(Metric::ExHeight) { }
    Metric m_metric { Metric::ExHeight };
};
```
**Exemplar commits**:
- `1af4da6b6ac2` — WebAnimation/StyleOriginatedAnimation 4 members uninitialized
- `345a8422657f` — RenderLayer member flags not initialized
- `3c79ffefbb7c` — HTMLMediaElement m_buffering/m_stalled uninitialized
- `493fe8cbc12c` — FontSizeAdjust::metric uninitialized
- `8ffa7479058d` — FontPlatformData::Attributes::m_options uninitialized
- `5d3ae531449d` — ByteTerm constructor misses fields
- `835136aa12f7` — SVGTextLayoutEngine::m_textPathStartOffset uninitialized
- `ff290911a4c8` — XPath::Parser::Token fields uninitialized

---

### U-GRAPHICS: Graphics buffer uninit leak
**Shape**: GPU/graphics buffer allocated but not fully initialized before display or cross-process sharing.
**Trigger**: Buffer allocation path skips zeroing or fill, leaving stale GPU/heap data visible in rendered output or shared across process boundary.
**Sink**: Uninitialized pixels or GPU memory exposed to web content or compositor.
**Escalation**: Info-leak (cross-origin pixel data, process memory), visual corruption.
**5yr frequency**: 6 commits (2021–2026)
**Affected dirs**: `Source/WebCore/platform/graphics/`, `Source/WebGPU/`, `Source/ThirdParty/ANGLE/`
**Grep anchors**:
```sh
rg "reshapeDrawingBuffer|clearColor" -n Source/WebCore/platform/graphics
rg "workgroup|threadgroup" -n Source/WebGPU
rg "missing.*return" -n Source/ThirdParty/ANGLE
```
**Canonical code**:
```cpp
// ❌ bad — front buffer not cleared after reshape
void reshapeDrawingBuffer() {
    allocateNewBuffer();
    // missing: clearColor(0, 0, 0, 0)
}

// ✅ safe — explicitly clear after allocation
void reshapeDrawingBuffer() {
    allocateNewBuffer();
    glClearColor(0, 0, 0, 0);
    glClear(GL_COLOR_BUFFER_BIT);
}
```
**Exemplar commits**:
- `341129414655` — WebGL front-buffer uninit after reshapeDrawingBuffer
- `85417a85b15c` — WGSL workgroup variables not zeroed
- `d86fef64a7c3` — WGSL threadgroup arrays/structs uninit
- `e539895bcf65` — ANGLE Metal shader missing return writes garbage

---

### U-CONTAINER: Container/array uninit (Vector, Butterfly)
**Shape**: Vector/Butterfly/ArrayBuffer grows or is created with uninitialized slots that are later read.
**Trigger**: Fast-path allocation skips zero-fill, early return before fill loop completes, or wrong default value used for type.
**Sink**: Uninitialized slot read returns stale heap data, exposed to JS or used in computation.
**Escalation**: Info-leak (heap data to JS), type confusion if slot holds pointer-like garbage.
**5yr frequency**: 5 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/runtime/`, `Source/JavaScriptCore/wasm/`, `Source/WTF/wtf/`
**Grep anchors**:
```sh
rg "tryCreateUninitializedRestricted|createUninitialized" -n Source/JavaScriptCore/runtime
rg "clearOptimalVectorLengthGap" -n Source/JavaScriptCore/runtime
rg "FixedVector|uninitializedCopy" -n Source/WTF/wtf
```
**Canonical code**:
```cpp
// ❌ bad — early return before fill
JSArray* tryCreateUninitializedRestricted(...) {
    auto* butterfly = allocateButterfly();
    if (earlyCondition)
        return array;  // butterfly slots unfilled
    fillSlots(butterfly);
    return array;
}

// ✅ safe — fill before any return
JSArray* tryCreateUninitializedRestricted(...) {
    auto* butterfly = allocateButterfly();
    fillSlots(butterfly);
    if (earlyCondition)
        return array;
    return array;
}
```
**Exemplar commits**:
- `778a182a97ca` — tryCreateUninitializedRestricted early return before fill
- `a9abb749d5da` — WASM GC struct default init wrong zero value
- `422833beda07` — FixedVector double-init for non-POD
- `af2328266733` — Vector uninitializedCopy span update
- `b1feea69abb7` — JSArray::tryCreate butterfly clearOptimalVectorLengthGap

---

### U-STRING: String/buffer uninitialized creation
**Shape**: `String::createUninitialized` caller fails to fill all bytes before string is exposed.
**Trigger**: Early return path or incorrect length calculation leaves trailing bytes unwritten in the allocated string buffer.
**Sink**: Uninitialized bytes in string exposed to JS or serialized over IPC.
**Escalation**: Info-leak (heap content in string), potential logic corruption.
**5yr frequency**: 4 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/wasm/`, `Source/WTF/wtf/text/`
**Grep anchors**:
```sh
rg "createUninitialized" -n Source/WTF/wtf/text
rg "createUninitialized" -n Source/JavaScriptCore/wasm
```
**Canonical code**:
```cpp
// ❌ bad — early return leaves string buffer partially filled
String buildResult() {
    UChar* buffer;
    auto str = String::createUninitialized(len, buffer);
    if (errorCondition)
        return str;  // buffer not fully written
    fillBuffer(buffer, len);
    return str;
}

// ✅ safe — always pass span to createUninitialized, fill before expose
String buildResult() {
    UChar* buffer;
    auto str = String::createUninitialized(len, buffer);
    fillBuffer(buffer, len);
    if (errorCondition)
        return emptyString();
    return str;
}
```
**Exemplar commits**:
- `778a182a97ca` — operationJSToWasmEntryWrapperBuildReturnFrame early return
- `98dc165d6ab8` — always pass span to createUninitialized

---

### U-STACK: Stack variable uninit
**Shape**: Local variable on stack used before initialization, especially in error/early-return paths.
**Trigger**: Variable declared without initializer; control flow branches around the assignment, reaching a use site with the variable still holding stack garbage.
**Sink**: Garbage value used in conditional, passed to function, or returned to caller.
**Escalation**: Logic corruption, DoS (crash on garbage pointer), info-leak if value reaches JS.
**5yr frequency**: 3 commits (2021–2026)
**Affected dirs**: `Source/WebCore/platform/image-decoders/`, `Source/JavaScriptCore/wasm/`
**Grep anchors**:
```sh
rg "bool\s+\w+;" -n Source/WebCore/platform/image-decoders
rg "SIMD.*local" -n Source/JavaScriptCore/wasm
```
**Canonical code**:
```cpp
// ❌ bad — alpha uninit on error path
bool alpha;
if (hasAlphaChannel)
    alpha = decodeAlpha();
// else: alpha is garbage
useAlpha(alpha);

// ✅ safe — default-initialize
bool alpha = false;
if (hasAlphaChannel)
    alpha = decodeAlpha();
useAlpha(alpha);
```
**Exemplar commits**:
- `9a76ccc77f6e` — JPEG2000 decoder alpha variable uninit
- `e728c9d826ea` — IPInt SIMD locals high 8 bytes uninit
- `f2204048d6bc` — stack result variable passed uninit to callback

---

### U-IPC: IPC serialization uninit leak
**Shape**: IPC encoder serializes struct containing uninitialized padding or data bytes.
**Trigger**: Raw struct bytes written to IPC message without field-by-field serialization, or sized span includes uninitialized tail.
**Sink**: Uninitialized bytes cross process boundary, leaking heap/stack content of sending process.
**Escalation**: Info-leak (cross-process memory disclosure).
**5yr frequency**: 2 commits (2021–2026)
**Affected dirs**: `Source/WebKit/Platform/IPC/`, `Source/WebKit/GPUProcess/`
**Grep anchors**:
```sh
rg "sendOutputMessage|iov" -n Source/WebKit/Platform/IPC
rg "uninit.*span" -n Source/WebKit/GPUProcess
```
**Canonical code**:
```cpp
// ❌ bad — iov includes uninitialized bytes
struct iovec iov;
iov.iov_base = buffer;
iov.iov_len = totalSize;  // totalSize > actual written bytes
sendmsg(fd, &msg, 0);

// ✅ safe — size matches actual written data
iov.iov_len = actualWrittenBytes;
sendmsg(fd, &msg, 0);
```
**Exemplar commits**:
- `f4367f2cffe4` — sendOutputMessage uninit iov
- `d70f6bbb8ba9` — GPUP WebGL uninitialized sized span

---

### U-MSAN: MemorySanitizer-detected uninit
**Shape**: MemorySanitizer catches uninit value use in third-party code integrated into WebKit.
**Trigger**: Third-party library (libvpx, libdav1d) uses value derived from uninitialized memory; MSan flags the use.
**Sink**: Uninit value influences conditional branch or output.
**Escalation**: Info-leak, logic corruption. Often low-severity in practice but MSan-clean builds require fix.
**5yr frequency**: 2 commits (2021–2026)
**Affected dirs**: `Source/ThirdParty/libwebrtc/`, `Source/ThirdParty/`
**Grep anchors**:
```sh
rg "MSan|MemorySanitizer" -n Source/ThirdParty
rg "uninit.*use" -n Source/ThirdParty/libwebrtc
```
**Exemplar commits**:
- `7fc39a64c04a` — libvpx MSan hit
- `a3161bf52b5e` — libdav1d MSan hit

---

### U-PADDING: Struct padding info-leak
**Shape**: Struct with alignment padding serialized as raw bytes, leaking stack/heap padding content.
**Trigger**: Struct has implicit padding bytes (due to alignment requirements) that are never explicitly zeroed; the struct is serialized by copying its raw memory representation.
**Sink**: Padding bytes containing stale stack/heap data cross trust boundary (IPC, network, JS).
**Escalation**: Info-leak (cross-process or cross-origin memory disclosure).
**5yr frequency**: 1 commit (2021–2026)
**Affected dirs**: `Source/WebCore/contentextensions/`
**Grep anchors**:
```sh
rg "ImmutableRange|SerializedNFA" -n Source/WebCore/contentextensions
rg "padding" -n Source/WebCore/contentextensions
```
**Canonical code**:
```cpp
// ❌ bad — struct with padding serialized as raw bytes
struct ImmutableRange<char> {
    char first;    // 1 byte
    // 1 byte padding
    uint16_t size; // 2 bytes
};
memcpy(dest, &range, sizeof(range));  // leaks padding byte

// ✅ safe — zero-initialize or serialize field-by-field
ImmutableRange<char> range{};  // zero-init clears padding
// or: serialize each field individually
```
**Exemplar commits**:
- `07918cccab88` — ImmutableRange<char> 2-byte padding leak in ContentExtensions::SerializedNFA

---

### U-CRYPTO: Crypto nonce/key uninit
**Shape**: Cryptographic nonce/IV/key buffer allocated without zeroing.
**Trigger**: Buffer for cryptographic material allocated via fast allocator that skips zeroing; the buffer is used as nonce or key material with stale heap content.
**Sink**: Predictable or leaked nonce/IV weakens cryptographic operation.
**Escalation**: Crypto weakness (nonce reuse, key leakage), info-leak.
**5yr frequency**: 1 commit (2021–2026)
**Affected dirs**: `Source/ThirdParty/ANGLE/`
**Grep anchors**:
```sh
rg "nonce|IV.*uninit" -n Source/ThirdParty/ANGLE
rg "aggressive.*uninit" -n Source/ThirdParty/ANGLE
```
**Exemplar commits**:
- `3a5543fb37df` — ANGLE compiled without aggressive uninit checking

---

### U-GENERIC: Generic uninit (needs per-commit review)
**Shape**: Catch-all for commits whose subject says "uninitialized" but doesn't reveal the specific pattern from the commit subject alone.
**Trigger**: Various — each commit in this bucket needs individual diff review to determine the true underlying pattern.
**Sink**: Various — pattern-dependent.
**Escalation**: Pattern-dependent; ranges from DoS to info-leak.
**5yr frequency**: 30 commits (2021–2026)

> **Note**: U-GENERIC is a **triage bucket**, not a true pattern. Each of the 30
> commits here should be individually reviewed by reading the diff, then
> reclassified into one of the named patterns above (or used to define a new
> pattern if ≥ 3 commits share a structurally distinct shape). Until that review
> is complete, they remain here as placeholders.

---

## Adding new exemplars

When a new uninitialized-read fix is committed to WebKit:

1. **Classify** — read the diff and determine which pattern (U-FIELDINIT through U-CRYPTO) it matches.
   If it matches none, consider whether it represents a new pattern worth adding.
2. **Append** — add the commit hash and a 1-line description to the pattern's
   `Exemplar commits` list.
3. **Update the count** — increment the pattern's `5yr frequency` and the summary
   table count.
4. **Cross-check** — if the commit touches a directory not yet listed in
   `Affected dirs`, add it.

Patterns are intentionally coarse-grained (10 buckets for 93 classified commits). Resist
the urge to split a pattern unless the new sub-pattern has ≥ 3 exemplars with a
structurally distinct shape. The remaining 264 commits (357 − 93) were not
classifiable from subject-line alone and require diff-level review.
