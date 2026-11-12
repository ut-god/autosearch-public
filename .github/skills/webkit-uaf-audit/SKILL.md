---
name: webkit-uaf-audit
description: Deep audit playbook for use-after-free, double-free, and race-to-UAF bugs in WebKit. Consult when the target method has lambdas, async dispatch (RunLoop / WorkQueue / IPC reply / Promise / Microtask), refcounted or raw-pointer fields, ownership transfers, or holds an iterator/reference across mutations of the underlying collection. Returns a verdict (HIGH/MED/LOW risk) plus exact unchecked sites and the missing capture/guard, suitable to drop into a CLAIM.
---

# WebKit UAF Audit Skill

This is the deep playbook for catching WebKit's #1 memory-safety bug
class. The goal is a HIGH/MED/LOW risk verdict on the target method,
backed by exact file:line evidence and the specific guard that's missing.

If you can answer "no" to every question in section 2 you should return
to the parent audit prompt with a `verified:` clean. Otherwise, follow
section 3 to extract the exact unchecked site for your CLAIM.

## 1. When this skill applies

Consult this skill when ANY of these hold for the target method:

- A `[this]`, `[&]`, or named-member capture in any lambda, `WTF::Function`,
  `std::function`, `CompletionHandler`, or callback.
- A call to `RunLoop::main().dispatch(`, `WorkQueue::dispatch(`,
  `callOnMainThread(`, `callOnMainRunLoop(`, `BinarySemaphore::wait(`,
  `Promise::resolve(`, or any `sendWithAsyncReply(` IPC call.
- A field of type `RefPtr<T>`, `Ref<T>`, `WeakPtr<T>`, `CheckedPtr<T>`,
  `RetainPtr<T>`, raw pointer, raw reference, or `T*`.
- The method registers a callback into an external library
  (libpng, libjpeg, libwebp, libavif, libjxl, ICU, Skia, libcurl, ...)
  via a function-pointer.
- The method holds an iterator, reference, span, or raw `data()` pointer
  across a `vector.append(...)`, `vector.remove(...)`, `map.add(...)`,
  `map.remove(...)`, or `clear()` on the same container.
- The method is invoked during teardown (dtor, finalizer, `removed`
  callback, `willBeRemoved`, `disconnectedFromOwner`, `dispose`,
  `stopped`).
- The method caches a raw pointer from a buffer/array and calls a
  function that might reallocate it.
- The method uses a custom allocator/freelist (not standard malloc/new).
- The method is a move-assignment operator for a smart pointer or
  resource wrapper.
- The method stores raw pointers in a HashMap/HashSet/Vector where the
  pointed-to objects have independent lifetimes.

If NONE of the above triggers fire, return to the parent prompt with
a TRIVIAL clean — this skill cannot help.

## 2. The 16-question checklist

Answer ALL questions that match the triggers in Section 1. Multiple
patterns can co-exist in a single method.

### Q1. Is `this` captured raw across an async boundary? *(Pattern P-01)*

For each lambda / callback in the method:

- What's the capture list?
- Where will it run? (Same call stack? Next RunLoop tick? IPC reply?
  Worker thread? Promise microtask?)

**Risk patterns (flag these):**

```cpp
// ❌ raw `this` into RunLoop tick
RunLoop::main().dispatch([this] {
    m_field->doX();        // *this may be dead by the next tick
});

// ❌ raw `this` into IPC async reply
m_connection->sendWithAsyncReply(Messages::Foo::Bar(arg),
    [this] (auto result) {
        m_field = result;  // *this may be dead by the time reply lands
    });

// ❌ raw `this` into worker
m_workQueue->dispatch([this] {
    accessSharedState();   // owner may have died on the main thread
});
```

**Safe patterns (don't flag these):**

```cpp
// ✅ Ref capture extends lifetime
RunLoop::main().dispatch([protectedThis = Ref { *this }] {
    protectedThis->doX();
});

// ✅ WeakPtr with explicit nullcheck on use
m_workQueue->dispatch([weakThis = WeakPtr { *this }] {
    if (auto strongThis = weakThis.get())
        strongThis->doX();
});

// ✅ Const-ref capture of a small POD argument is fine; the issue
//    is only with `this` and `m_` capture across async.
```

If you find a raw `this` capture into ANY async boundary without a
`Ref { *this }` / `WeakPtr { *this }` / equivalent: **HIGH risk UAF**.
Record the exact dispatch line as the unchecked_op.

### Q2. Are smart-pointer fields cleared mid-method? *(Pattern P-05)*

```cpp
RefPtr<Decoder> decoder = m_decoder;   // bumps refcount
decoder->prepare();                     // OK
m_decoder = nullptr;                    // refcount may drop to 1 (just `decoder`)
auto& cached = *m_cachedThing;          // ❌ if m_cachedThing was owned by m_decoder
```

The pattern: a method clears `m_X` and then accesses `m_Y` whose
lifetime was tied to `m_X`. Run:

```sh
rg "m_\w+\s*=\s*nullptr" -n <target_file> | head
rg "m_\w+\.clear\(\)" -n <target_file> | head
```

For each clear/null assignment, check whether sibling `m_` fields
become dangling.

### Q3. Reentrancy through callbacks? *(Pattern P-06)*

Does any call inside this method's body invoke a user callback (event
handler, observer, JS execution, IPC dispatch) that could re-enter
the same class and free `m_` members?

Pattern to grep:
```sh
rg "(notify|fire|dispatch|invoke|call)Listeners?|EventListener::handleEvent|JSC::call" -n <target_file>
```

If the method modifies `m_` fields AROUND a callback site (read before,
mutate after), and the callback could re-enter and clear those fields:
**HIGH risk UAF**.

### Q4. Iterator / reference invalidation? *(Pattern P-07)*

```cpp
for (auto& item : m_vector) {        // iterator captured
    item.process();                   // process() may grow m_vector
                                      // → realloc → iterator dangles
}

auto& ref = m_hashMap.get(key);       // ref into bucket
m_hashMap.add(otherKey, otherValue);  // may rehash → ref dangles
ref.use();
```

For each ranged-for, iterator, reference, or raw `data()` taken from
a container: does any line between capture and use mutate that
container? Common WebKit cases:

- `m_observers` (Vector or HashSet) being iterated while observers
  are added/removed in callbacks.
- `m_pendingTasks` Vector iterated and tasks invoked, where a task
  schedules a new task into `m_pendingTasks`.

### Q5. IPC / cross-process lifetime mismatch? *(Pattern P-02)*

For methods in `Source/WebKit/UIProcess/`, `WebProcess/`, `GPUProcess/`,
`NetworkProcess/`:

- Does the method capture `this` into an IPC reply lambda?
- Could the connection survive a process restart, and the receiver
  die in between?
- Is the Connection itself the owner, or does the receiver hold the
  Connection?

Pattern:
```cpp
// ❌ assumes both ends live equally long
connection->sendWithAsyncReply(Messages::Foo(), [this] (auto reply) {
    handleReply(reply);
});

// ✅ uses WeakPtr for crash-safety
connection->sendWithAsyncReply(Messages::Foo(),
    [weakThis = WeakPtr { *this }] (auto reply) {
        if (auto strongThis = weakThis.get())
            strongThis->handleReply(reply);
    });
```

### Q6. Dtor / finalizer ordering? *(Pattern P-13, partial)*

In a destructor, finalizer (`~Foo()`, `JSCell::destroy`, `visitChildren`),
or stop/dispose method:

- Are touched fields guaranteed alive? GC visit order is unspecified;
  `m_referenceToOtherCell` may already have been finalized.
- Is `m_field->method()` safe if `m_field` was the only ref-holder
  to a now-dropped Ref?
- For JSC: never call into JS from a finalizer — execution may have
  shut down.

### Q7. Cached pointer invalidated by reallocation?

**Pattern P-08.** A method caches a raw pointer (`m_vector`, `data()`,
`basePointer()`) from a buffer/array/Wasm memory, then calls a function
that could grow or reallocate that backing store. The cached pointer
becomes stale.

**Risk patterns (flag these):**

```cpp
// ❌ cached data() pointer across memory.grow()
auto* ptr = typedArray->m_vector;
memory->grow(newPageCount);     // backing store realloc'd
ptr[offset] = value;            // UAF — ptr is stale

// ❌ span.data() across vector.reserveCapacity()
auto* base = span.data();
vector.reserveCapacity(newSize); // may realloc the backing buffer
base[i] = x;                    // UAF — base is stale

// ❌ buffer->data() across ArrayBuffer.resize()
auto* raw = buffer->data();
buffer->resize(newByteLength);   // backing store may move
memcpy(raw, src, len);           // UAF — raw is stale
```

**Safe patterns (don't flag these):**

```cpp
// ✅ re-fetch pointer after potential reallocation
memory->grow(newPageCount);
auto* ptr = typedArray->m_vector;  // fresh pointer after grow
ptr[offset] = value;

// ✅ refreshVector() callback keeps TypedArray in sync
memory->grow(newPageCount, [&](auto*) {
    typedArray->refreshVector();
});
```

Grep anchors:
```sh
rg "basePointer\(\)|->data\(\)|m_vector|->memory\(\)" -n <target_file> | head
rg "grow\(|resize\(|reserveCapacity\(" -n <target_file> | head
```

If a cached pointer survives a call that could reallocate its backing
store: **HIGH risk UAF**. Record the stale pointer's last use as the
unchecked_op. (Ref: commit `6b357f32c607` — Wasm resizable buffer grow
UAF.)

### Q8. Custom allocator freelist reuse?

**Pattern P-09.** Code uses a custom freelist/pool allocator. A freed
object is recycled while stale pointers from a prior save/snapshot still
reference it. Especially dangerous when recycled objects contain function
pointers or return addresses.

**Risk patterns (flag these):**

```cpp
// ❌ freelist recycles ParenContext while stale pointer exists
ParenContext* ctx = allocParenContext();
saveState(ctx);           // snapshot stores raw ctx pointer
freeParenContext(ctx);    // ctx returned to freelist
ParenContext* reused = allocParenContext();  // same address recycled
restoreState();           // uses snapshot's stale ctx → UAF/IP control

// ❌ MetaAllocator FreeSpaceNode reuse with dangling neighbor pointer
auto* node = freelist->remove(best);
// stale neighbor pointers in adjacent nodes still reference `node`
```

**Safe patterns (don't flag these):**

```cpp
// ✅ null stale pointer on free
freeParenContext(ctx);
ctx = nullptr;
savedState.parenContext = nullptr;

// ✅ epoch / generation counter guards reuse
auto epoch = allocator.currentEpoch();
// ... after free + realloc ...
if (snapshot.epoch != allocator.currentEpoch())
    return;  // stale — do not dereference
```

Grep anchors:
```sh
rg "allocate.*Context|freeList|ParenContext|FreeSpaceNode" -n <target_file> | head
```

If a freed object is returned to a custom freelist while stale pointers
survive: **HIGH risk UAF** (with potential IP control if the recycled
object contains function pointers). (Ref: commit `2d16551f697d` — YARR
ParenContext UAF with IP control.)

### Q9. Self-move-assignment of smart pointer / wrapper?

**Pattern P-10.** `operator=(T&&)` releases the old resource before
reading `other`. If `this == &other`, that's a UAF. The move-and-swap
idiom prevents this.

**Risk patterns (flag these):**

```cpp
// ❌ release-before-read in operator=(T&&) without self-assignment guard
BlockPtr& operator=(BlockPtr&& other) {
    Block_release(m_block);   // releases current
    m_block = other.m_block;  // if this == &other, m_block is already freed
    other.m_block = nullptr;
    return *this;
}
```

**Safe patterns (don't flag these):**

```cpp
// ✅ move-and-swap idiom
BlockPtr& operator=(BlockPtr&& other) {
    BlockPtr tmp(std::move(other));
    swap(m_block, tmp.m_block);
    return *this;
}

// ✅ explicit self-assignment guard
BlockPtr& operator=(BlockPtr&& other) {
    if (this == &other)
        return *this;
    Block_release(m_block);
    m_block = other.m_block;
    other.m_block = nullptr;
    return *this;
}
```

Grep anchors:
```sh
rg "operator=\(.*&&\)" -n <target_file> | head
```

If `operator=(T&&)` releases the old resource before reading from
`other` and has no self-assignment guard: **HIGH risk UAF**. (Ref:
commit `4af68f95d78c` — BlockPtr self-move UAF.)

### Q10. Raw pointer in container key/value outlives pointee?

**Pattern P-11.** `HashMap<T*, V>`, `HashSet<T*>`, or `Vector<T*>`
stores raw pointers to objects whose lifetime is managed elsewhere.
Object destruction + container iteration = UAF.

**Risk patterns (flag these):**

```cpp
// ❌ raw pointer as HashMap key survives object deletion
HashMap<IDBTransaction*, Vector<IDBRequest*>> m_transactionMap;
// ...
transaction->abort();        // transaction destroyed
for (auto& pair : m_transactionMap) {
    pair.key->doSomething(); // UAF — transaction is dead
}

// ❌ raw pointer in HashSet during cache eviction
HashSet<CachedResource*> m_liveResources;
resource->deleteIfPossible();        // resource freed
m_liveResources.contains(resource);  // UAF — dangling lookup
```

**Safe patterns (don't flag these):**

```cpp
// ✅ WeakHashMap drops entries when pointee is destroyed
WeakHashMap<IDBTransaction, Vector<IDBRequest*>> m_transactionMap;

// ✅ HashMap with Ref keeps pointee alive
HashMap<Ref<CachedResource>, Metadata> m_resourceMap;

// ✅ explicit remove-before-delete
m_transactionMap.remove(transaction);
transaction->destroy();
```

Grep anchors:
```sh
rg "HashMap<.*\*|HashSet<.*\*" -n <target_file> | head
```

If a container holds raw pointers and the pointed-to objects can be
destroyed independently (especially in transaction rollback, cache
eviction, or registry cleanup paths): **HIGH risk UAF**. (Ref: commit
`d2ef3504e98a` — IDB MemoryBackingStoreTransaction raw pointer key.)

### Q11. Cross-thread destruction race? *(Pattern P-12)*

**Pattern P-12** (17 bugs in 5 yr). A non-thread-safe ref-counted object
is ref'd/deref'd from a background thread, or destroyed on a different
thread from where it was created.

**Risk patterns (flag these):**

```cpp
// ❌ non-ThreadSafeRefCounted object captured into background queue
m_workQueue->dispatch([protectedThis = Ref { *this }] {
    protectedThis->process();  // deref() on background thread
    // destructor may run here — wrong thread
});

// ❌ member written on one thread, read on another without lock
void onBackgroundThread() { m_buffer = newBuffer; }
void onMainThread()       { m_buffer->use(); }  // torn read → UAF
```

**Safe patterns (don't flag these):**

```cpp
// ✅ ThreadSafeRefCounted allows cross-thread ref/deref
class MyObj : public ThreadSafeRefCounted<MyObj> { ... };

// ✅ ensure destruction on main thread
callOnMainThread([prevent = WTFMove(prevent)] { });

// ✅ ThreadSafeWeakPtr for weak cross-thread references
ThreadSafeWeakPtr<MyObj> weakRef;
```

Grep anchors:
```sh
rg "ThreadSafeRefCounted|m_workQueue->dispatch|callOnMainThread" -n <target_file> | head
```

If a non-ThreadSafeRefCounted object can be deref'd or destroyed on a
background thread: **HIGH risk RACE_TO_UAF**.

### Q12. GC/finalizer ordering? *(Pattern P-13)*

**Pattern P-13** (6 bugs in 5 yr). In JSC code, a raw JSValue or
JSObject reference is held without a WriteBarrier, or a finalizer
touches a cell that may already have been collected.

**Risk patterns (flag these):**

```cpp
// ❌ raw JSObject* without WriteBarrier — GC may collect it
JSObject* m_cachedTarget;  // not visited, not write-barriered

// ❌ C++ holds raw cell ref across safepoint
auto* cell = jsCast<JSObject*>(value);
callToJS();               // GC safepoint — cell may be collected
cell->get(vm, ident);     // UAF — cell is freed

// ❌ finalizer touches sibling cell
void destroy(JSCell* cell) {
    static_cast<MyObj*>(cell)->m_other->release(); // m_other may be finalized
}
```

**Safe patterns (don't flag these):**

```cpp
// ✅ WriteBarrier prevents GC from collecting the target
WriteBarrier<JSObject> m_cachedTarget;

// ✅ visitAdditionalChildren keeps related cells alive
void visitAdditionalChildren(JSC::SlotVisitor& visitor) {
    visitor.append(m_cachedTarget);
}
```

Grep anchors:
```sh
rg "writeBarrier|visitChildren|globalObject\(\)" -n <target_file> | head
```

If a raw cell reference can survive a GC safepoint, or a finalizer
touches a potentially-finalized cell: **HIGH risk UAF**.

### Q13. WeakPtr deref without nullcheck? *(Pattern P-16)*

**Pattern P-16** (11 bugs in 5 yr). A `WeakPtr` is dereferenced with
`->` or `*` without first checking whether it is null.

**Risk patterns (flag these):**

```cpp
// ❌ direct deref of WeakPtr without nullcheck
m_weakDocument->updateLayout();  // if pointee destroyed → null deref / UAF

// ❌ captured WeakPtr used without check
[weakThis = WeakPtr { *this }] {
    weakThis->process();  // weakThis may be null
};
```

**Safe patterns (don't flag these):**

```cpp
// ✅ nullcheck before use
if (auto strong = m_weakDocument.get())
    strong->updateLayout();

// ✅ guard in lambda
[weakThis = WeakPtr { *this }] {
    if (auto strongThis = weakThis.get())
        strongThis->process();
};
```

Grep anchors:
```sh
rg "weakThis->|m_weak\w*->" -n <target_file> | head
```

If a `WeakPtr` is dereferenced without a preceding nullcheck and the
pointee can be destroyed between capture and use: **HIGH risk UAF**.

### Q14. DOM/Render dirty-state deref? *(Pattern P-17)*

**Pattern P-17** (7 bugs in 5 yr). Rendering or style code accesses a
renderer, z-order list, or computed style on a dirty render tree. Style
resolution triggered mid-method destroys the renderer being used.

**Risk patterns (flag these):**

```cpp
// ❌ renderer() used after style resolution that may destroy it
auto* renderer = element->renderer();
element->computedStyle();          // triggers style resolution
renderer->repaint();               // renderer may have been destroyed

// ❌ z-order list accessed on dirty tree
auto* list = renderer->zOrderList();
document->updateStyleIfNeeded();   // may destroy/rebuild z-order lists
list->first()->paint();            // stale pointer
```

**Safe patterns (don't flag these):**

```cpp
// ✅ re-check renderer() after style resolution
element->computedStyle();
if (auto* renderer = element->renderer())
    renderer->repaint();

// ✅ ensure tree is clean before accessing renderer
document->updateLayoutIfNeeded();
auto* renderer = element->renderer();
```

Grep anchors:
```sh
rg "computedStyle|zOrderList|getOrCreate" -n <target_file> | head
```

If a renderer/style pointer is used after a call that can trigger
style resolution: **HIGH risk UAF**.

### Q15. Ref-counting / ownership model error? *(Pattern P-19)*

**Pattern P-19** (10 bugs in 5 yr). A function returns a raw reference
or pointer from a RefPtr-held object, or code uses a Page/Document/Frame
after a call that could destroy it without Ref-protecting it first.

**Risk patterns (flag these):**

```cpp
// ❌ raw reference survives the last RefPtr
Document& getDoc() { return *m_document; }  // caller gets raw ref
// ... if m_document is reassigned/cleared, raw ref dangles

// ❌ Page used after call that may destroy it
page->mainFrame().script().execute(code);
// execute() can close the page → page is destroyed
page->updateRendering();  // UAF — page is dead
```

**Safe patterns (don't flag these):**

```cpp
// ✅ return RefPtr so caller holds a ref
RefPtr<Document> getDoc() { return m_document; }

// ✅ protect with Ref before potentially-destroying call
Ref document = m_document;
document->processEvent();  // even if m_document cleared, `document` lives
```

Grep anchors:
```sh
rg "return \*m_|Ref<Page>|Ref<Document>" -n <target_file> | head
```

If a raw reference outlives the last RefPtr to the same object, or an
owning object is used after a call that can destroy it: **HIGH risk UAF**.

### Q16. Dangling pointer to destroyed temporary? *(Pattern P-20)*

**Pattern P-20** (9 bugs in 5 yr). Code takes a raw pointer (`.data()`,
`.span()`) from a temporary object. The temporary dies at the semicolon,
leaving a dangling pointer.

**Risk patterns (flag these):**

```cpp
// ❌ .data() on temporary CString — dies at semicolon
auto* p = str.utf8().data();   // CString temporary destroyed
use(p);                         // UAF — p is dangling

// ❌ reference to temporary Vector
auto& first = makeTemporaryVector()[0];  // temporary destroyed
first.use();                              // UAF
```

**Safe patterns (don't flag these):**

```cpp
// ✅ store temporary in a local variable first
auto utf8 = str.utf8();
auto* p = utf8.data();
use(p);                    // utf8 still alive

// ✅ use result inline without storing pointer
process(str.utf8().data());  // temporary lives through full-expression
```

Grep anchors:
```sh
rg "utf8\(\)\.data\(\)|latin1\(\)\.data\(\)" -n <target_file> | head
```

If `.data()` or a reference is taken from a temporary and stored past
the full-expression: **HIGH risk UAF**.

## 3. Extracting the CLAIM

If any question above returns HIGH risk:

1. **unchecked_op.file:line** — the SITE where the UAF would manifest.
   Almost always the dispatch / use line, NOT the field declaration.
2. **missing_check.file:line** — where the protectedThis / WeakPtr
   capture or the explicit guard should be inserted. Usually the
   capture-list of the offending lambda.
3. **patch_counterfactual** — minimal unified diff that adds the
   missing capture or guard. Single line preferred. For example:

   ```diff
   - RunLoop::main().dispatch([this] {
   + RunLoop::main().dispatch([protectedThis = Ref { *this }] {
        m_field->doX();
   ```

4. **reachability** — trace the dispatch site back to an entry in
   `{{ATTACKER_SURFACE}}`. If the dispatch is unreachable from any
   attacker surface, downgrade severity to Low and consider whether
   the bug class should be `n/a` instead.
5. **primitive** — describe what the attacker controls. For UAF this
   is usually "controlled-content read/write at an old object's
   address" or "vtable dispatch on freed memory."
6. **bug_class**: `UAF` if the dangling deref is single-threaded;
   `RACE_TO_UAF` if exploitation requires racing two threads;
   `DOUBLE_FREE` only if the same destructor runs twice.

## 4. Reference materials

Read these from the same directory if you need depth:

- `uaf-pattern-catalog.md` — the 18-pattern taxonomy derived from
  5 years (333 commits) of WebKit UAF history. Each pattern has
  shape, trigger, sink, escalation, frequency, grep anchors,
  canonical code, and exemplar commits. Start here to understand
  which patterns are most frequent in the target's subsystem.
- `smart-pointer-cheatsheet.md` — full Ref/RefPtr/WeakPtr/CheckedPtr/
  BlockPtr/WeakHashMap/ThreadSafeWeakPtr/CheckedRef semantics table
  with refcount-transition rules and self-move-assignment safety.
- `async-capture-patterns.md` — every WebKit async-dispatch primitive
  with the correct vs incorrect capture style, including RunLoop::Timer
  cross-thread destruction and background RunLoop ownership.
- `wasm-jit-uaf-patterns.md` — UAF patterns specific to JSC's Wasm
  and JIT pipelines: memory backing store lifetime, DFG graph mutation
  hazards, YARR backtracking state machine, IPInt/LLInt bounds checking.

## 5. What this skill won't help with

- Pure integer-overflow bugs → `webkit-overflow-audit` skill.
- Type-confusion bugs (jsCast, vtable layout) → `webkit-type-confusion-audit`.
- Pure threading races without UAF (e.g., torn read of an int) →
  `webkit-race-audit`.
- Wasm-specific semantic/spec-compliance bugs (not memory-safety) →
  separate Wasm audit skill.

If the target method has bug surface in multiple classes, consult
each relevant skill in turn. Multi-class methods are common in WebKit
(IPC entry points often have both UAF and TC risk).

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
