# WebKit UAF Pattern Catalog

> **Methodology**: Bottom-up classification of 333 UAF-related commits across WebKit
> (2021-01-01 → 2026-05-31). Each commit was tagged by keyword and diff-level
> structural analysis, then merged into deduplicated pattern buckets. The result
> is a taxonomy of **18 recurring UAF shapes** that account for the full
> population. This catalog replaces the earlier individual-CVE listing with a
> structural approach: audit for *patterns*, not individual bugs.

---

## Summary table

| ID | Pattern | 5yr Count |
|----|---------|:---------:|
| P-15 | CheckedPtr-caught lifetime bug | 38 |
| P-12 | Cross-thread destruction race | 17 |
| P-11 | Raw pointer in container outlives pointee | 14 |
| P-03 | Teardown/detach callback on freed object | 12 |
| P-06 | Reentrancy through callback mutates m_ fields | 11 |
| P-16 | WeakPtr deref without nullcheck | 11 |
| P-19 | Ref-counting / ownership model error | 10 |
| P-01 | Raw this across async boundary | 9 |
| P-07 | Iterator/reference invalidation | 9 |
| P-20 | Dangling pointer to destroyed temporary | 9 |
| P-17 | DOM/Render dirty-state deref | 7 |
| P-13 | GC/finalizer ordering | 6 |
| P-08 | Cached pointer after buffer reallocation | 4 |
| P-09 | Custom allocator freelist reuse | 2 |
| P-10 | Self-move-assignment | 2 |
| P-18 | Double free | 2 |
| P-05 | Smart-pointer cleared mid-method | 1 |
| P-14 | Compiler-IR stale reference | 1 |

---

## Pattern entries

---

### P-01: Raw this across async boundary
**Shape**: A C++ `this` pointer (or raw reference to the owning object) is captured by value in a lambda/block that executes asynchronously, after the object may have been destroyed.
**Trigger**: The caller posts a `callOnMainThread`, dispatches to a work queue, or stores a callback/block; the captured raw pointer outlives the pointee because no protecting reference is taken.
**Sink**: The lambda body dereferences `this` or the raw pointer on a later run-loop turn.
**Escalation**: IP control (vtable deref on freed object), arbitrary R/W, DoS.
**5yr frequency**: 9 commits (2021–2026)
**Affected dirs**: `Source/WebCore/page/`, `Source/WebCore/Modules/`, `Source/WebKit/`, `Source/WebGPU/`
**Grep anchors**:
```sh
rg "callOnMainThread\(\[" -n Source/WebCore Source/WebKit
rg "dispatch_async.*\bthis\b" -n Source/WebCore Source/WebKit
```
**Canonical code**:
```cpp
// ❌ bad — raw this captured across async boundary
callOnMainThread([this] {
    m_field->doSomething();   // this may be freed
});

// ✅ safe — protect with WeakPtr
callOnMainThread([weakSelf = WeakPtr { *this }] {
    if (!weakSelf)
        return;
    weakSelf->m_field->doSomething();
});
```
**Exemplar commits**:
- `30946aa4c66c` (2023) — Raw this in callOnMainThread in ResourceUsageOverlay
- `882406de5528` (2023) — Raw Document ref in CDM callback
- `ce446a1cea92` (2023) — Raw this in callOnMainThread for MediaPlayer
- `f1cfd5a3139a` (2022) — Raw C++ this in Obj-C blocks in SystemPreviewController
- `140660a4096b` (2024) — Raw pointer in recordCommand lambda in RenderBundleEncoder

---

### P-03: Teardown/detach callback on freed object
**Shape**: An object registers itself (or a raw pointer to itself) with a subsystem; during teardown the deregistration either never runs, runs in the wrong order, or the callback fires after the pointee is already freed.
**Trigger**: Destruction sequencing error — the pointee is freed before the delegate/client/callback registration is unwound, or `prepareForDestruction` misses a supplement.
**Sink**: The subsystem fires the callback, which dereferences the stale pointer.
**Escalation**: IP control (vtable), DoS.
**5yr frequency**: 12 commits (2021–2026)
**Affected dirs**: `Source/WebCore/workers/`, `Source/WebCore/platform/mac/`, `Source/WebCore/Modules/fetch/`, `Source/WebKit/`
**Grep anchors**:
```sh
rg "m_client\b" -n Source/WebCore/workers
rg "prepareForDestruction" -n Source/WebCore/dom
rg "setDelegate\(nil\)" -n Source/WebCore/platform/mac
```
**Canonical code**:
```cpp
// ❌ bad — raw m_client outlives pointee
class WorkerScriptLoader {
    Client* m_client;  // raw, never cleared on teardown
};

// ✅ safe — weak back-reference or explicit detach
class WorkerScriptLoader {
    WeakPtr<Client> m_client;
};
```
**Exemplar commits**:
- `19642719bec4` (2022) — Raw m_client in WorkerScriptLoader
- `868fdd2f6088` (2022) — Stale raw _scrollbar in ObjC callback
- `a23df0dfbec0` (2022) — Stale ScrollerMac pointer after delegate replacement
- `a330ea7722cd` (2023) — VM destroyed between prepareForDestruction and destructor
- `8f96cc81ef90` (2023) — Premature teardown of FetchBodyConsumer
- `ff119714d9a5` (2023) — Mismatched supplement name prevents removal during prepareForDestruction

---

### P-05: Smart-pointer cleared mid-method
**Shape**: A method holds a smart pointer (RefPtr, std::unique_ptr) in a member variable; a call within the method causes re-entrancy or a callback that nullifies the member, and the method continues to use the now-null/freed pointee.
**Trigger**: A mid-method call triggers code that clears `m_source`, `m_stream`, or similar member.
**Sink**: Subsequent code in the same method dereferences the stale local alias or the now-null member.
**Escalation**: DoS (null deref), potential IP control if the pointer is reused.
**5yr frequency**: 1 commit (2021–2026)
**Affected dirs**: `Source/WebCore/Modules/`
**Grep anchors**:
```sh
rg "m_readableStreamSource" -n Source/WebCore/Modules/mediacaptureprocessing
```
**Canonical code**:
```cpp
// ❌ bad — m_readableStreamSource cleared mid-method
void MediaStreamTrackProcessor::doWork() {
    m_readableStreamSource->enqueue(...);  // callback clears m_readableStreamSource
    m_readableStreamSource->close();       // null deref
}

// ✅ safe — protect with local Ref
void MediaStreamTrackProcessor::doWork() {
    RefPtr source = m_readableStreamSource;
    if (!source)
        return;
    source->enqueue(...);
    source->close();
}
```
**Exemplar commits**:
- `08e3cb08fc23` (2024) — m_readableStreamSource nullified mid-method in MediaStreamTrackProcessor

---

### P-06: Reentrancy through callback mutates m_ fields
**Shape**: A method iterates over or dereferences member state; a synchronous callback (JS event, promise reaction, GC, style resolution) during that method mutates or frees the same state.
**Trigger**: JavaScript-observable operations (promise settle, event dispatch, style flush, GC) that re-enter C++ code and mutate the data being iterated/used.
**Sink**: The original method resumes with dangling pointers, stale iterators, or freed backing stores.
**Escalation**: IP control (vtable on freed node), arbitrary R/W, DoS.
**5yr frequency**: 11 commits (2021–2026)
**Affected dirs**: `Source/WebCore/dom/`, `Source/WebCore/rendering/`, `Source/WebCore/css/`, `Source/WebCore/Modules/`, `Source/WebCore/html/canvas/`
**Grep anchors**:
```sh
rg "updateStyleIfNeeded|resolveStyle" -n Source/WebCore/css
rg "dispatchEvent|fireEvent" -n Source/WebCore/dom
rg "DeferredPromise::reject" -n Source/WebCore/bindings
```
**Canonical code**:
```cpp
// ❌ bad — JS callback reenters and frees document
void commitStyles() {
    updateStyleIfNeeded();  // calls JS, which navigates document
    m_document->body();     // m_document freed
}

// ✅ safe — protect document with Ref and check validity
void commitStyles() {
    Ref document = m_document;
    updateStyleIfNeeded();
    if (!document->frame())
        return;
    document->body();
}
```
**Exemplar commits**:
- `4b12cc4800e1` (2022) — Style flush during z-order iteration
- `633fbf1eab41` (2023) — DeferredPromise::reject reenters JS, deallocates Document
- `85fd2302d16a` (2023) — commitStyles calls updateStyleIfNeeded which reenters JS
- `777fe1501522` (2024) — addSVGRendererUpdate reentrantly removes element
- `cd5d1b32f5a4` (2024) — ViewTransition callback destroys RenderLayers mid-iteration
- `c86498286572` (2024) — CanvasCaptureMediaStreamTrack callback triggers GC
- `eac7aa0748e7` (2023) — Event listener destroys ScriptExecutionContext
- `b46a8fcd809a` (2024) — Stream cancellation triggers GC collecting FetchResponse
- `f9641bf127f5` (2024) — getItemFromDatabase triggers connection close freeing m_cache
- `fe980dac0c6c` (2024) — rvfc callback navigates document clearing mid-iteration

---

### P-07: Iterator/reference invalidation
**Shape**: Code holds a C++ iterator, pointer, or reference into a container (Vector, HashMap, HashSet, Deque); a mutation (insert, remove, resize) during the same scope invalidates it.
**Trigger**: Container mutation during iteration (callback-driven or explicit), or capacity expansion that reallocates backing storage.
**Sink**: The stale iterator/pointer is dereferenced after the mutation.
**Escalation**: Heap-buffer-overflow → arbitrary R/W, DoS.
**5yr frequency**: 9 commits (2021–2026)
**Affected dirs**: `Source/WebCore/accessibility/`, `Source/WebCore/animation/`, `Source/WebCore/css/`, `Source/JavaScriptCore/b3/`, `Source/ThirdParty/libwebrtc/`
**Grep anchors**:
```sh
rg "for.*\b(begin|end)\(\)" -n Source/WebCore/accessibility
rg "m_timelines.*remove" -n Source/WebCore/animation
rg "Vector<.*>\s+m_" -n Source/JavaScriptCore/b3
```
**Canonical code**:
```cpp
// ❌ bad — mutation during iteration
for (auto& item : m_timelines) {
    item->tick();           // tick() may call removeTimeline()
}

// ✅ safe — copy or use index-safe iteration
auto copy = m_timelines;
for (auto& item : copy) {
    item->tick();
}
```
**Exemplar commits**:
- `04f0e806cbca` (2023) — WeakListHashSet mutation during AXObjectCache iteration
- `64a427a3f379` (2023) — removeTimeline mutates m_timelines during iteration
- `4dfdeb7f6ab6` (2023) — Vector capacity expansion invalidates references during reapply
- `cf373f0fc0d0` (2022) — B3IRGenerator stored in Vector, growth invalidates pointers
- `96745ccf6bd5` (2023) — libwebrtc deque modified during SendBufferedPackets iteration
- `f047d0a6e29e` (2024) — HashMap resize invalidates pointers during collectGlobals

---

### P-08: Cached pointer after buffer reallocation
**Shape**: Code stores a raw pointer (or Span) into a growable buffer (Vector, ArrayBuffer, Wasm memory); a subsequent operation grows/reallocates the buffer, leaving the pointer dangling.
**Trigger**: Buffer growth (Vector::append, memory.grow, realloc) after a raw pointer into the buffer was cached.
**Sink**: The cached pointer is read or written after reallocation.
**Escalation**: Heap-buffer-overflow, arbitrary R/W, info-leak.
**5yr frequency**: 4 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/wasm/`, `Source/WTF/wtf/url/`, `Source/JavaScriptCore/yarr/`, `Source/WebGPU/`
**Grep anchors**:
```sh
rg "m_data\b.*\bm_vector\b" -n Source/JavaScriptCore/wasm
rg "StringView.*Vector" -n Source/WTF/wtf/url
rg "getMappedRange" -n Source/WebGPU
```
**Canonical code**:
```cpp
// ❌ bad — raw pointer cached before grow
auto* ptr = m_memory->data();
m_memory->grow(newPages);   // reallocs backing
ptr[offset] = value;        // dangling write

// ✅ safe — re-derive pointer after growth
m_memory->grow(newPages);
auto* ptr = m_memory->data();
ptr[offset] = value;
```
**Exemplar commits**:
- `6b357f32c607` (2022) — Wasm memory grow invalidates m_data and m_vector
- `1325b97c04cd` (2023) — StringView references invalidated by Vector realloc in URLParser
- `561d0e5534c8` (2023) — Pointer into Vector storage invalidated during regex parsing
- `cf23d24d68de` (2024) — GPUBuffer getMappedRange raw pointer freed before use

---

### P-09: Custom allocator freelist reuse
**Shape**: A custom allocator (bump, freelist, slab) returns memory to its freelist; the memory is reused before all references to the old allocation are dead, or the freelist itself is corrupted.
**Trigger**: Free-to-freelist followed by allocation-from-same-slot, while a stale pointer still exists.
**Sink**: The stale pointer dereferences the now-reused memory, giving the attacker control of the "object" contents.
**Escalation**: IP control (fake vtable), arbitrary R/W.
**5yr frequency**: 2 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/yarr/`, `Source/bmalloc/`
**Grep anchors**:
```sh
rg "ParenContext" -n Source/JavaScriptCore/yarr
rg "FreeSpaceNode" -n Source/bmalloc
```
**Canonical code**:
```cpp
// ❌ bad — freelist reuse with stale pointer
parenContext->release(freeList);
// ... attacker-controlled allocation fills same slot ...
parenContext->getDisjunction();  // reads attacker data

// ✅ safe — null out pointer after release, or use type-safe allocator
parenContext->release(freeList);
parenContext = nullptr;
```
**Exemplar commits**:
- `2d16551f697d` (2021) — YARR ParenContext freelist reuse with IP control
- `98aa585d7ea2` (2022) — MetaAllocator FreeSpaceNode destructor not called

---

### P-10: Self-move-assignment
**Shape**: An object is move-assigned to itself (or a use-after-move occurs where the moved-from value is subsequently read).
**Trigger**: Container operations, swap-with-self, or constructor argument forwarding where source and destination alias.
**Sink**: The moved-from object's state (nulled-out pointer, empty string) is read.
**Escalation**: DoS (null deref), logic corruption.
**5yr frequency**: 2 commits (2021–2026)
**Affected dirs**: `Source/WTF/wtf/`, `Source/WebCore/css/`
**Grep anchors**:
```sh
rg "operator=.*&&" -n Source/WTF/wtf/BlockPtr.h
rg "WTFMove\(" -n Source/WebCore/css
```
**Canonical code**:
```cpp
// ❌ bad — release-before-read in move assignment (the real BlockPtr bug)
BlockPtr& operator=(BlockPtr&& other) {
    Block_release(m_block);          // frees current block
    m_block = std::exchange(other.m_block, nullptr);  // if this == &other, reads freed m_block
    return *this;
}

// ✅ safe — move-and-swap idiom
BlockPtr& operator=(BlockPtr&& other) {
    BlockPtr tmp(std::move(other));   // move-construct temp (nulls other)
    std::swap(m_block, tmp.m_block);  // swap: we get block, temp gets old
    return *this;                     // temp destructor releases old block
}
```
**Exemplar commits**:
- `4af68f95d78c` (2022) — BlockPtr self-move-assignment (release-before-read UAF)
- `40f4e5e1face` (2023) — Use-after-move of stops in StyleGradientImage constructor

---

### P-11: Raw pointer in container outlives pointee
**Shape**: A container (HashMap, Vector, member pointer) holds a raw `T*` to an object whose lifetime is managed elsewhere; the pointee is destroyed but the container entry is not cleared.
**Trigger**: The pointee's destructor does not remove its entry from the container, or the container is not notified of destruction.
**Sink**: A later lookup/iteration of the container dereferences the dangling entry.
**Escalation**: IP control (vtable), arbitrary R/W, DoS.
**5yr frequency**: 14 commits (2021–2026)
**Affected dirs**: `Source/WebKit/`, `Source/WebCore/platform/`, `Source/WebCore/Modules/indexeddb/`, `Source/WebCore/Modules/mediasource/`
**Grep anchors**:
```sh
rg "\braw\b.*pointer|(\*\s+m_\w+;)" -n Source/WebKit/UIProcess
rg "m_player\b" -n Source/WebCore/Modules/mediasource
rg "m_objectStore" -n Source/WebCore/Modules/indexeddb
```
**Canonical code**:
```cpp
// ❌ bad — raw pointer member outlives pointee
class MockMediaSourcePrivate {
    MediaPlayer* m_player;  // raw, no ref, no weak
};

// ✅ safe — use WeakPtr or CheckedRef
class MockMediaSourcePrivate {
    WeakPtr<MediaPlayer> m_player;
};
```
**Exemplar commits**:
- `0338ad61ac9c` (2022) — Raw m_pageChannel in WorkerInspectorProxy
- `1e46cd53f762` (2022) — Raw pointer to ScrollingTreeScrollingNode in ScrollerPairMac
- `4d861ff045d4` (2023) — Raw m_player in MockMediaSourcePrivate
- `5e2fbff61ae9` (2023) — Raw pointer in MemoryIndex to MemoryObjectStore
- `946b13e5e935` (2023) — Raw pointer in m_originalObjectStoreNames
- `9326bbd1cf1f` (2023) — Raw pointers in m_transactionOperationsInProgressQueue
- `9fe1180072fb` (2023) — Raw m_player in MediaPlayerPrivate

---

### P-12: Cross-thread destruction race
**Shape**: An object created on one thread is destroyed or accessed on another thread without thread-safe ref-counting or synchronization; the destructor races with a concurrent reader/writer.
**Trigger**: `deref()` on a non-thread-safe ref-counted object from a background thread, or a raw pointer shared across threads without locking.
**Sink**: The freed object is dereferenced on the other thread, or the destructor double-frees.
**Escalation**: Heap corruption, IP control, info-leak, DoS.
**5yr frequency**: 17 commits (2021–2026)
**Affected dirs**: `Source/WebKit/`, `Source/WebCore/platform/audio/`, `Source/WebCore/Modules/webaudio/`, `Source/WebCore/platform/mac/`, `Source/WebGPU/`
**Grep anchors**:
```sh
rg "callOnMainThread|ensureOnMainThread" -n Source/WebKit
rg "ThreadSafeRefCounted" -n Source/WebCore/platform/audio
rg "dispatch_async.*m_" -n Source/WebCore/platform/mac
```
**Canonical code**:
```cpp
// ❌ bad — non-thread-safe ref used cross-thread
void backgroundWork() {
    m_target->send(msg);  // m_target may be freed on main thread
}

// ✅ safe — use ThreadSafeRefCounted or protect via ensureOnMainThread
void backgroundWork() {
    Ref target = m_target;  // protect lifetime across threads
    target->send(msg);
}
```
**Exemplar commits**:
- `2a508351f154` (2022) — Raw m_target in RemoteConnectionToTarget cross-thread
- `33efffb67232` (2023) — ImageBuffer used on main after creation on work queue
- `3af977b5f7ff` (2024) — Single-threaded Adapter on secondary thread in WebGPU
- `49dc08fbc054` (2023) — String name() cross-thread
- `5b116606568b` (2023) — decodeAudioData background vs ArrayBuffer::transfer race
- `7d0a50fadc7c` (2023) — AudioBuffer channels detached while audio thread reads
- `880a52f6ce59` (2023) — LogIdentifier string cross-thread data race
- `9861733b659d` (2022) — NSScrollerImp cross-thread
- `f80743cbb13c` (2023) — AudioWorkletGlobalScope cross-thread ref/unref
- `330e342c4a4d` (2024) — MockRealtimeVideoSourceMac timer cross-thread destruction

---

### P-13: GC/finalizer ordering
**Shape**: A JavaScript-visible value (JSObject, JSValue, CodeBlock) is stored without a proper GC write-barrier or tracer visit; when GC runs, it collects the value while C++ still holds a raw reference.
**Trigger**: Missing `writeBarrier()`, missing `visitChildren()` override, or GC triggered at an unexpected point (during JIT compilation, during navigation).
**Sink**: The C++ code dereferences the GC-collected JSValue/JSObject.
**Escalation**: IP control (faked JSCell), arbitrary R/W, type confusion.
**5yr frequency**: 6 commits (2021–2026)
**Affected dirs**: `Source/WebCore/navigation/`, `Source/JavaScriptCore/b3/`, `Source/JavaScriptCore/dfg/`
**Grep anchors**:
```sh
rg "writeBarrier|visitAdditionalChildren" -n Source/WebCore/navigation
rg "globalObject\(\)" -n Source/JavaScriptCore/b3
```
**Canonical code**:
```cpp
// ❌ bad — raw JSValue without write-barrier
class NavigationAPIMethodTracker {
    JSC::JSValue m_info;  // no write-barrier, GC may collect
};

// ✅ safe — use WriteBarrier<>
class NavigationAPIMethodTracker {
    JSC::WriteBarrier<JSC::Unknown> m_info;
    void visitAdditionalChildren(JSC::AbstractSlotVisitor&);
};
```
**Exemplar commits**:
- `182d9c2cf11d` (2024) — NavigateEvent JSValue not GC-traced
- `686a6f293536` (2024) — NavigationAPIMethodTracker raw JSValue without write-barrier
- `cae26b36ccb9` (2022) — GC during B3::generate collects CodeBlock's globalObject

---

### P-14: Compiler-IR stale reference
**Shape**: The JIT compiler (DFG/FTL/B3) holds a pointer or iterator into IR data structures; a mid-compilation mutation (watchpoint invalidation, constant folding, block merging) invalidates the reference.
**Trigger**: Watchpoint fires during compilation, causing block restructuring while an iterator still points at the old block.
**Sink**: The stale IR pointer is dereferenced for code generation.
**Escalation**: JIT mis-compilation → type confusion → arbitrary R/W.
**5yr frequency**: 1 commit (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/dfg/`
**Grep anchors**:
```sh
rg "failedBlock|iterator_open|iterator_next" -n Source/JavaScriptCore/dfg
```
**Canonical code**:
```cpp
// ❌ bad — failedBlock dangling after watchpoint invalidation
BasicBlock* failedBlock = ...;
// watchpoint fires, blocks restructured
failedBlock->appendNode(...);  // dangling

// ✅ safe — re-derive block reference after invalidation point
auto* failedBlock = getOrCreateFailedBlock();
failedBlock->appendNode(...);
```
**Exemplar commits**:
- `3f4f81750dc5` (2023) — DFG iterator_open/iterator_next dangling failedBlock after watchpoint invalidation

---

### P-15: CheckedPtr-caught lifetime bug (meta-pattern)
> **Note**: P-15 is a **detection mechanism**, not a root-cause pattern. Each P-15
> bug has an underlying root cause that maps to another pattern (P-01, P-03, P-11,
> P-17, etc.). CheckedPtr/CheckedRef instrumentation converts what would be a
> silent exploitable UAF into a controlled crash. When auditing, classify the
> *root cause* using the other patterns — P-15 tells you CheckedPtr is working,
> not what the bug shape is.

**Shape**: A lifetime bug (dangling raw pointer, stale back-reference) is caught at runtime by WebKit's `CheckedPtr`/`CheckedRef` hardening infrastructure rather than shipping as an exploitable UAF.
**Trigger**: Same root causes as other patterns (P-01, P-03, P-11, etc.), but the pointer was wrapped in `CheckedPtr` which asserts on dangling deref.
**Sink**: `CheckedPtr::get()` or `CheckedRef::operator*` triggers a controlled crash instead of a silent UAF.
**Escalation**: DoS (controlled crash). Without CheckedPtr these would be IP control / arbitrary R/W.
**5yr frequency**: 38 commits (2021–2026)
**Affected dirs**: `Source/WebCore/rendering/`, `Source/WebCore/page/`, `Source/WebKit/`, `Source/WebCore/accessibility/`, `Source/WebCore/platform/`
**Grep anchors**:
```sh
rg "CheckedPtr|CheckedRef" -n Source/WebCore/rendering
rg "RELEASE_ASSERT.*isNotDestroyed\|checkedPtr" -n Source/WebCore
```
**Canonical code**:
```cpp
// CheckedPtr catches the bug at runtime:
// CRASH — CheckedRef detects dangling deref
auto& renderer = checkedRef();  // asserts if target freed

// The underlying fix is pattern-specific — e.g., protect with Ref:
Ref element = m_element;
element->updateStyle();
```
**Exemplar commits**:
- `d8bf29799f0f` (2024) — ::first-letter CheckedPtr crash
- `421f42aa5eba` (2024) — WebThermalMitigationObserver CheckedPtr crash
- `baf71d57603f` (2024) — WebScrollbarPartAnimationMac CheckedPtr crash
- `4c8d209dd76f` (2024) — NetworkResourceLoader::contentFilterDidBlock CheckedPtr crash
- `54845b1b8742` (2024) — Reddit with VoiceOver CheckedPtr crash

---

### P-16: WeakPtr deref without nullcheck
**Shape**: Code obtains a `WeakPtr` to an object but dereferences it (via `->` or `*`) without first checking for null; if the pointee has been destroyed, the WeakPtr is null and the deref crashes or, in unsafe casts, becomes a UAF.
**Trigger**: The pointee is destroyed between the point where the WeakPtr was captured and where it is dereferenced.
**Sink**: `weakPtr->method()` without prior `if (weakPtr)` check.
**Escalation**: DoS (null deref crash). In some cases, if the WeakPtr is unsafely cast, IP control.
**5yr frequency**: 11 commits (2021–2026)
**Affected dirs**: `Source/WebCore/platform/`, `Source/WebCore/Modules/mediasession/`, `Source/WebCore/Modules/mediarecorder/`
**Grep anchors**:
```sh
rg "weakThis->" -n Source/WebCore/Modules
rg "WeakPtr.*get\(\)" -n Source/WebCore/platform
```
**Canonical code**:
```cpp
// ❌ bad — WeakPtr deref without nullcheck
auto weakThis = WeakPtr { *this };
doAsyncWork([weakThis] {
    weakThis->complete();  // crashes if *this destroyed
});

// ✅ safe — check before deref
auto weakThis = WeakPtr { *this };
doAsyncWork([weakThis] {
    if (!weakThis)
        return;
    weakThis->complete();
});
```
**Exemplar commits**:
- `28838f616b1d` (2023) — WeakPtr<PlatformSpeechSynthesizer>::get() crash
- `b728e584a883` (2024) — Missing weakThis nullcheck in MediaRecorderPrivateWriter
- `d1154cafe842` (2024) — Missing weakThis nullcheck in MediaKeySession::load

---

### P-17: DOM/Render dirty-state deref
**Shape**: Code accesses a renderer, style, or layout object while the DOM/render tree is in a dirty (inconsistent) state — e.g., after a DOM mutation but before layout, or during style resolution when renderers are being torn down.
**Trigger**: Accessing `renderer()`, z-order lists, or computed style on an element whose render tree is mid-mutation.
**Sink**: The returned pointer is stale (renderer destroyed, z-order list freed).
**Escalation**: IP control (renderer vtable), DoS.
**5yr frequency**: 7 commits (2021–2026)
**Affected dirs**: `Source/WebCore/rendering/`, `Source/WebCore/css/`, `Source/WebCore/html/`
**Grep anchors**:
```sh
rg "computedStyle|getComputedStyle" -n Source/WebCore/css
rg "zOrderList\|m_posZOrderList" -n Source/WebCore/rendering
rg "setIsHiddenByOverflowTruncation" -n Source/WebCore/rendering
```
**Canonical code**:
```cpp
// ❌ bad — computedStyle triggers style resolution that destroys renderer
auto* style = element->computedStyle();
element->renderer()->repaint();  // renderer was destroyed during style resolution

// ✅ safe — check renderer after style resolution
auto* style = element->computedStyle();
if (auto* renderer = element->renderer())
    renderer->repaint();
```
**Exemplar commits**:
- `cd7e28cf47f6` (2023) — computedStyle on option triggers style resolution destroying RenderMenuList
- `adc161c58c5a` (2024) — setIsHiddenByOverflowTruncation stale z-order list pointers

---

### P-18: Double free
**Shape**: An object or memory region is freed twice — either through explicit `delete`/`free` duplication, or through two ownership paths both attempting to release the same allocation.
**Trigger**: Two code paths both believe they own the allocation, or error-handling frees memory that the normal path also frees.
**Sink**: The second `free()`/`delete` corrupts heap metadata.
**Escalation**: Heap corruption → arbitrary R/W, IP control.
**5yr frequency**: 2 commits (2021–2026)
**Affected dirs**: `Source/bmalloc/libpas/`, `Tools/`
**Grep anchors**:
```sh
rg "double.free|twice" -n Source/bmalloc/libpas
```
**Canonical code**:
```cpp
// ❌ bad — two owners both free
free(buffer);
// ... later ...
free(buffer);  // double free

// ✅ safe — null after free, or use unique_ptr
free(buffer);
buffer = nullptr;
```
**Exemplar commits**:
- `1521a0feb21f` (2023) — libPAS double-free hardening
- `669cd08179b2` (2024) — Skia double-free in WebKitTestRunner

---

### P-19: Ref-counting / ownership model error
**Shape**: An object's ref-count is managed incorrectly — a `Ref`/`RefPtr` is not taken when it should be, a raw reference escapes a `RefPtr` scope, or an ownership cycle prevents destruction and then a weak path dangles.
**Trigger**: Returning a raw `CSSValue&` from a function that held a `RefPtr`, failing to Ref-protect a `Page` or `Document` across a call that may destroy it, or ownership cycles between DOM and rendering.
**Sink**: The raw reference/pointer is used after the last `RefPtr` goes out of scope.
**Escalation**: IP control (vtable deref), arbitrary R/W, DoS.
**5yr frequency**: 10 commits (2021–2026)
**Affected dirs**: `Source/WebCore/css/`, `Source/WebCore/rendering/`, `Source/WebCore/page/`, `Source/WebCore/dom/`
**Grep anchors**:
```sh
rg "propertyValue\b|rawValue" -n Source/WebCore/css
rg "Ref<Page>|Ref<Document>" -n Source/WebCore/page
rg "inlineItemsList\|m_inlineItems" -n Source/WebCore/rendering
```
**Canonical code**:
```cpp
// ❌ bad — raw CSSValue& escapes RefPtr scope
const CSSValue& value() {
    return *m_value;  // m_value is RefPtr; caller gets raw ref
}
// caller: auto& v = style.value(); style.clear(); v.cssText(); // UAF

// ✅ safe — return RefPtr
RefPtr<CSSValue> value() {
    return m_value;
}
```
**Exemplar commits**:
- `13885ac44906` (2023) — RenderStyle→DOM ownership cycle
- `85237c9326a2` (2024) — propertyValue returns raw CSSValue from RefPtr
- `84ebf5141996` (2024) — Style::Resolver raw reference freed during ViewTransition
- `421cb9e942e1` (2024) — RenderObject freed while still in inlineItemsList
- `ddbf9329b2ca` (2024) — Page not Ref-protected in setContentsSize

---

### P-20: Dangling pointer to destroyed temporary
**Shape**: Code stores a raw pointer or reference to data owned by a C++ temporary (typically `CString` from `String::utf8()`, or a `Vector` returned by value); the temporary is destroyed at the end of the full-expression, leaving the pointer dangling.
**Trigger**: `auto* p = str.utf8().data();` — the `CString` temporary dies at the semicolon.
**Sink**: `p` is passed to a function or stored for later use after the temporary is gone.
**Escalation**: Info-leak (reading freed heap), heap corruption if written, DoS.
**5yr frequency**: 9 commits (2021–2026)
**Affected dirs**: `Source/WebKit/`, `Source/WebCore/`, `Source/JavaScriptCore/`, `Source/WTF/wtf/text/`
**Grep anchors**:
```sh
rg "utf8\(\)\.data\(\)" -n Source/WebKit Source/WebCore
rg "Span.*temporary\|rvalue.*StringTypeAdapter" -n Source/WTF
```
**Canonical code**:
```cpp
// ❌ bad — raw pointer to destroyed temporary
auto* cstr = url.utf8().data();  // CString temporary destroyed here
LOG("%s", cstr);                 // dangling

// ✅ safe — keep the CString alive
auto utf8 = url.utf8();
auto* cstr = utf8.data();
LOG("%s", cstr);
```
**Exemplar commits**:
- `50a93108b100` (2023) — utf8().data() stored after CString temporary destroyed
- `a8249e0ac40b` (2023) — Same pattern — utf8().data()
- `ba10f958479c` (2023) — Same
- `c44357db93e1` (2023) — Same
- `e77d53c31b3d` (2023) — Same
- `c19a6292aab1` (2024) — Span references temporary vector destroyed
- `d8d29d461845` (2024) — rvalue String passed to StringTypeAdapter not retained

---

## Adding new exemplars

When a new UAF fix is committed to WebKit:

1. **Classify** — read the diff and determine which pattern (P-01 through P-20) it matches.
   If it matches none, consider whether it represents a new pattern worth adding.
2. **Append** — add the commit hash and a 1-line description to the pattern's
   `Exemplar commits` list.
3. **Update the count** — increment the pattern's `5yr frequency` and the summary
   table count.
4. **Cross-check** — if the commit touches a directory not yet listed in
   `Affected dirs`, add it.

Patterns are intentionally coarse-grained (18 buckets for 333 commits). Resist
the urge to split a pattern unless the new sub-pattern has ≥ 3 exemplars with a
structurally distinct shape.
