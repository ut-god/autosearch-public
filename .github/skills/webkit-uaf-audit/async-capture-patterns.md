# Async Dispatch Capture Patterns

Every place WebKit dispatches async work, with the correct vs incorrect
lambda-capture style. Use this as the source of truth when answering
the raw-this-capture question (Q1) and cross-thread questions (Q5, Q11)
in `SKILL.md`.

## RunLoop dispatch

```cpp
// ❌ UAF candidate — `*this` may die before the tick runs
RunLoop::main().dispatch([this] {
    m_field->method();
});

// ✅ extends `*this` lifetime
RunLoop::main().dispatch([protectedThis = Ref { *this }] {
    protectedThis->m_field->method();
});

// ✅ best when the work is optional (skip if owner died)
RunLoop::main().dispatch([weakThis = WeakPtr { *this }] {
    if (auto strongThis = weakThis.get())
        strongThis->m_field->method();
});
```

Same rules for:
- `RunLoop::current().dispatch(...)`
- `callOnMainThread(...)` / `callOnMainRunLoop(...)`
- `RunLoop::main().dispatchAfter(delay, ...)`

## WorkQueue dispatch

```cpp
// ❌ cross-thread raw `this`
m_workQueue->dispatch([this] {
    accessSharedState();
});

// ✅
m_workQueue->dispatch([protectedThis = Ref { *this }] {
    protectedThis->accessSharedState();
});
```

WorkQueue is especially dangerous because:
- The owning thread can release its ref while the worker is mid-task.
- Workers don't run on a known thread; they may interleave with main.
- If the worker mutates `m_` state without a lock, that's also a
  RACE_TO_UAF candidate.

## IPC `sendWithAsyncReply`

```cpp
// ❌ classic — the connection survives the receiver
m_connection->sendWithAsyncReply(Messages::Foo::Bar(arg),
    [this] (Result result) {
        m_field = result;
    });

// ✅ WeakPtr is the correct pattern; the reply is fire-and-forget,
//    so it's OK to drop on owner death
m_connection->sendWithAsyncReply(Messages::Foo::Bar(arg),
    [weakThis = WeakPtr { *this }] (Result result) {
        if (auto strongThis = weakThis.get())
            strongThis->m_field = result;
    });
```

Note the asymmetric lifetime: the IPC `Connection` outlives most
receivers (especially during process termination races). Holding a
strong `Ref { *this }` here can mask the bug into a leak instead.
**`WeakPtr` is the canonical pattern for IPC reply lambdas.**

## Promise / `then` chains

```cpp
// ❌ Promise resolution may run on next microtask
promise->then([this] (auto value) {
    handle(value);
});

// ✅
promise->then([protectedThis = Ref { *this }] (auto value) {
    protectedThis->handle(value);
});
```

## Microtask queue

```cpp
// ❌
queueMicrotask([this] { tick(); });

// ✅
queueMicrotask([protectedThis = Ref { *this }] { protectedThis->tick(); });
```

## CompletionHandler

```cpp
// ❌
auto handler = CompletionHandler<void(int)>([this] (int result) {
    m_callback(result);
});

// ✅
auto handler = CompletionHandler<void(int)>(
    [protectedThis = Ref { *this }] (int result) {
        protectedThis->m_callback(result);
    });
```

`CompletionHandler` is fire-once and asserts that it ran; this
*detects* leaks (a missed call) but does NOT prevent UAFs in the
captured `this`.

## Function-pointer callbacks into C libraries

```cpp
// libpng example — png_set_progressive_read_fn takes a function pointer
// and a void* user-data. WebKit usually passes `this` as user-data.

png_set_progressive_read_fn(m_png, this,
    &PNGImageReader::headerAvailableCallback,    // static fn
    &PNGImageReader::rowAvailableCallback,
    &PNGImageReader::frameCompleteCallback);

// The callbacks unpack `this`:
void PNGImageReader::headerAvailableCallback(png_struct* png, png_info* info)
{
    auto* self = static_cast<PNGImageReader*>(png_get_progressive_ptr(png));
    self->headerAvailable(info);   // ❌ UAF if `self` died
}
```

To audit:
- Find the registration site (`png_set_*`, `WebPInitialize*`, etc.)
- Verify what owns the `this` passed as user-data. Is the libpng
  context torn down before / synchronously with the WebKit object?
- The classic WebKit image-decoder UAF is exactly this: WebKit object
  destroys, libpng callback fires (because libpng's state was on the
  decode stack), accesses freed `self`.

## Member-function-pointer dispatch

```cpp
auto fn = std::bind(&Foo::method, this);   // captures raw `this`
// fn() called later → UAF if `this` died
```

Look for `std::bind(...this...)`, `mem_fn`, `BoundFunction` —
all carry the same `[this]` risk.

## Microbenchmark for `this` capture

If you see `[this]` in the source, in less than 30 seconds you should
be able to answer:

1. **When does this lambda run?** (now, next tick, IPC reply, ...)
2. **Who owns the lambda's lifetime?** (Connection, RunLoop, libpng, ...)
3. **Can `*this` outlive the owner of the lambda?** If no → safe.
   If yes or unsure → UAF candidate.

Most safe `[this]` usage in WebKit is in immediate-call contexts
(passing a lambda to `std::sort`, `for_each`, iterator-based loops).
Anything that crosses an async boundary, an FFI boundary, or a
cross-thread queue should use `Ref { *this }` or `WeakPtr { *this }`.

## RunLoop::Timer cross-thread destruction

When a `RunLoop::Timer` is bound to a background `RunLoop::create()`
thread, the timer object MUST be destroyed on that same thread.
Destroying it from the main thread (e.g., in the owning object's
destructor) races with timer firing on the background thread → UAF of
the timer object itself.

```cpp
// ❌ Timer as value member, destroyed by main-thread dtor
class Foo {
    RunLoop::Timer m_timer;      // bound to m_runLoop (background)
    Ref<RunLoop> m_runLoop;
    ~Foo() {
        // m_timer destroyed here on main thread
        // but it may be firing on m_runLoop's thread → UAF
    }
};

// ✅ Timer as unique_ptr, destruction dispatched to its RunLoop
class Foo {
    std::unique_ptr<RunLoop::Timer> m_timer;
    Ref<RunLoop> m_runLoop;
    ~Foo() {
        m_runLoop->dispatch([timer = std::exchange(m_timer, nullptr)] {
            // timer destroyed on the correct thread
        });
    }
};
```

See commit `330e342c4a4d` (MockRealtimeVideoSourceMac cross-thread
timer UAF) for a real-world example of this bug and fix.

## Background RunLoop ownership

`RunLoop::create()` returns a `Ref<RunLoop>`. The background thread
must hold a ref to keep the RunLoop alive. `stop()` must be called
before releasing the last ref. If the main thread releases its ref
while a timer is firing, the timer callback races with RunLoop
teardown.

```cpp
// ❌ RunLoop ref released while timer may be firing
m_runLoop = nullptr;  // RunLoop may be destroyed while timer callback is in-flight

// ✅ Stop first, then release
m_runLoop->stop();    // waits for in-flight callbacks to complete
m_runLoop = nullptr;  // safe now
```
