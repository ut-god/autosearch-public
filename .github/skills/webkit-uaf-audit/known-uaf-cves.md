# Known WebKit UAF CVE Patterns

Illustrative — not exhaustive. Useful as priors when auditing files
in similar areas. If the file you're auditing is in a directory that
appears below, the historical pattern probably hasn't changed and
the same bug shape is worth looking for again.

This file is intentionally short and pattern-focused, not a CVE
database. Update opportunistically when refinement promotes a new
R-NN catalog entry derived from a real WebKit fix.

## Image decoder callback UAFs

**Affected directories**:
`Source/WebCore/platform/image-decoders/{png,jpeg,webp,avif,jxl}/`

**Pattern**: WebKit's image decoder registers C-callbacks with
libpng / libjpeg / libwebp / libavif / libjxl. The callbacks pack
`this` as user-data. When the WebKit decoder is destroyed during
an in-flight decode (renderer abort, navigation, repaint), the
external library's already-on-the-stack callback fires on freed
`self`.

**Audit anchor**: any function name ending in `Callback`, registered
via `*_set_*_fn` or equivalent. Trace user-data ownership.

## IPC async reply UAFs

**Affected directories**: `Source/WebKit/UIProcess/`,
`Source/WebKit/WebProcess/`, `Source/WebKit/GPUProcess/`

**Pattern**: receiver captures `[this]` in a `sendWithAsyncReply`
lambda. The IPC `Connection` outlives the receiver during process
restart / sandbox crash. Reply arrives, dereferences freed `this`.

**Audit anchor**: grep `sendWithAsyncReply.*\[this\]`.

## Document / Frame teardown UAFs

**Affected directories**: `Source/WebCore/dom/`,
`Source/WebCore/loader/`, `Source/WebCore/page/`

**Pattern**: a method on `Document` or `Frame` schedules work
(navigation, parsing, GC) and the document/frame is detached
before the work runs. Common offenders: `RunLoop::main().dispatch`
inside `Document::implicitClose` / `Frame::detached`.

**Audit anchor**: any method called during `disconnectedFromOwner`,
`willBeRemovedFromFrame`, `stopLoading`, that captures fields.

## Worker / WebWorker shutdown UAFs

**Affected directories**: `Source/WebCore/workers/`

**Pattern**: a worker thread holds a `WeakPtr` to a main-thread
object. Worker shutdown races with main-thread teardown; the
WeakPtr is observed alive in one tick and dereferenced after the
target dies in the next.

**Audit anchor**: cross-thread `WeakPtr` use without a Lock.

## JSC GC / finalizer UAFs

**Affected directories**: `Source/JavaScriptCore/runtime/`

**Pattern**: in `visitChildren` / `destroy`, a JSC cell touches
another cell that may have already been finalized in the same GC
cycle. Visit order across cells is undefined.

**Audit anchor**: any non-`Base::method(visitor)` call inside a
`visitChildren` override.

## GraphicsContextGL state UAFs

**Affected directories**: `Source/WebCore/platform/graphics/`

**Pattern**: GPU process holds GL state that the WebProcess can
invalidate via IPC. Compositor thread reads stale GL state after
WebProcess released the underlying texture.

**Audit anchor**: any `GraphicsContextGL` method that takes raw
texture IDs or framebuffer handles.

## Vector / HashMap iterator invalidation

**Affected directories**: codebase-wide; especially common in
`Source/WebCore/dom/` (event dispatch), `Source/WebCore/loader/`
(resource caches), `Source/WebKit/UIProcess/` (process lists).

**Pattern**: ranged-for over `m_observers` while observer callbacks
mutate `m_observers`. Even with `copy()` first, the COPY's iterators
still point into now-freed observer objects if observer destruction
is synchronous on remove.

**Audit anchor**: `for (... : m_collection)` immediately followed by
calls into `m_collection`'s elements.

## What's NOT in this list

- Type-confusion CVEs in JSC bindings → see `webkit-type-confusion-audit`.
- Wasm-specific bugs → see `webkit-wasm-audit`.
- Pure integer-overflow CVEs → see `webkit-overflow-audit`.

These often co-occur with UAFs (e.g., a TC primitive enables a UAF),
but the *root cause* category drives which skill applies first.
