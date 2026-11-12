# WebKit Smart Pointer Cheatsheet

Reference table for the auditor. Consult when classifying field
ownership during the SKILL.md checklist (especially Q2, Q10–Q13).

## Ownership types

| Type | Owns? | Nullable | Increments refcount on copy? | Use when |
|---|---|---|---|---|
| `Ref<T>` | yes (one ref) | **no** — non-null invariant | yes | guaranteed-alive holder |
| `RefPtr<T>` | yes | yes | yes | optional holder |
| `WeakPtr<T>` | no | yes (becomes null on owner death) | no | non-owning back-reference |
| `CheckedPtr<T>` | no | poisons if dangling (release-asserts on use) | no | hardened raw pointer |
| `RetainPtr<T>` | yes (CF/NS retain) | yes | yes (calls `CFRetain` / `[obj retain]`) | CoreFoundation / Cocoa objects |
| `Markable<T>` | embeds T | sentinel-based | n/a (value type) | optional small POD |
| `T*` (raw) | **no** | yes | no | only when you can prove the raw pointer's lifetime by other means |
| `T&` (raw) | **no** | no | no | guaranteed-alive scope-local reference |
| `BlockPtr<T>` | yes (block retain) | yes | yes (`Block_copy`) | Obj-C block wrapper |
| `WeakHashMap<K,V>` | no (weak keys) | keys auto-expire | n/a (container) | HashMap where keys are weak refs; entries expire when key dies |
| `ThreadSafeWeakPtr<T>` | no | yes (becomes null) | no | Cross-thread-safe WeakPtr; control block uses atomic refcount |
| `CheckedRef<T>` | no | **no** — non-null invariant | no | Like CheckedPtr but non-nullable; release-asserts on dangling |
| `UniquelyOwned<T>` | yes (unique) | yes | no (move-only) | Unique ownership with InlineWeakPtr observation support |
| `InlineWeakPtr<T>` | no | yes | no | Weak observer for UniquelyOwned objects |

## Refcount-transition rules

- `Ref<T> r = ...` — bumps refcount by 1.
- `Ref<T> r = WTFMove(other)` — moves; no refcount change.
- `RefPtr<T> p = nullptr` — drops the ref this RefPtr held; if it was
  the last, the object is destroyed (synchronously, in this thread).
- `m_field.clear()` — same as above for the field's RefPtr.
- `m_field = nullptr` — same.
- `auto p = WTFMove(m_field)` — `m_field` is now null; `p` owns.
- `Ref<T>` cannot be assigned `nullptr` (the type forbids it). To
  drop a `Ref<T>` field you must move it out or destroy the owning
  object.

## Capture-style cheatsheet for lambdas

| Capture | Refcount effect | Safe across async? |
|---|---|---|
| `[this]` | none | **NO** — `*this` may die |
| `[protectedThis = Ref { *this }]` | +1 ref to `*this` | **yes** — keeps alive |
| `[weakThis = WeakPtr { *this }]` | none | **yes IF nullchecked** before deref |
| `[strongRef = m_field]` (RefPtr) | +1 to *m_field | **yes** — keeps target alive even if `*this` dies |
| `[&]` | none (refs only) | **NO** — same problem as `[this]` plus all stack vars |
| `[=]` | copies values; refs/ptrs become raw | **NO** for raw pointers; equivalent to `[this]` |

## Common WebKit field declarations decoded

```cpp
RefPtr<Document> m_document;          // owning, nullable, refcount-bump on copy
WeakPtr<Element> m_target;            // non-owning; check operator bool()
CheckedPtr<Foo> m_cachedFoo;          // raw-pointer-fast, dangles → release-assert
Ref<Page> protectedPage();            // returns by-value; caller owns extra ref
const RefPtr<Frame>& frame() const;   // returns by-const-ref; caller borrows
WeakHashMap<Element, String> m_names;   // weak-key map; entries expire when Element dies
ThreadSafeWeakPtr<Foo> m_crossThread;   // safe to promote from any thread
CheckedRef<Bar> m_bar;                  // non-null, release-asserts on dangling
UniquelyOwned<Baz> m_owned;             // unique owner with weak observation
```

## Anti-patterns to flag

- `Ref<T>` field stored in a class that may outlive the object the
  field references (creates strong-cycle / leak; not a UAF, but
  a related smell).
- `WeakPtr<T>` deref without a nullcheck:
  ```cpp
  m_observer->onChange();   // ❌ UAF if m_observer's target died
  ```
  Should be:
  ```cpp
  if (auto observer = m_observer.get())
      observer->onChange();
  ```
- Raw `T*` field with no documented owner. Every raw pointer field
  must have an explicit comment or a sibling `RefPtr` that owns it,
  or it's a UAF candidate by construction.

## Self-move-assignment safety

When `a = std::move(a)` is called on a smart pointer, the move-assignment
operator must not release the resource before reading the source. The safe
pattern is move-and-swap.

| Type | Self-move safe? | Mechanism |
|------|:---:|---|
| `Ref<T>` | ✅ | n/a (non-nullable, no assignment) |
| `RefPtr<T>` | ✅ | move-and-swap |
| `RetainPtr<T>` | ✅ | move-and-swap |
| `GRefPtr<T>` | ✅ | move-and-swap |
| `BlockPtr<T>` | ✅ (post-fix) | move-and-swap (commit 4af68f95d78c) |
| `Function<>` | ✅ | delegates to unique_ptr |
| `CompletionHandler<>` | ✅ | delegates to Function |
| `UniqueRef<T>` | ✅ | no move assignment defined |

Anti-pattern to flag:
```cpp
// ❌ release-before-read in move assignment
T& operator=(T&& other) {
    release(m_ptr);                    // frees current resource
    m_ptr = std::exchange(other.m_ptr, nullptr);  // reads other.m_ptr — UAF if this == &other
    return *this;
}

// ✅ move-and-swap
T& operator=(T&& other) {
    T tmp(std::move(other));
    std::swap(m_ptr, tmp.m_ptr);
    return *this;
}
```

## When in doubt

If you can't classify a field's ownership in 30 seconds of reading,
flag it as audit-worthy. WebKit code where the ownership story is
unclear has historically had UAFs.
