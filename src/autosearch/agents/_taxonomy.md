### Classes

- `HEAP_OVERFLOW` — out-of-bounds **write** into heap-allocated storage
  (linear or struct-relative). Includes wild-pointer writes whose
  base resolves to a heap chunk.
- `STACK_OVERFLOW` — out-of-bounds **write** into a stack-allocated
  buffer or local. Distinct from HEAP_OVERFLOW: different exploit
  primitive (return-address / canaries / argument-frame), different
  mitigation surface (no malloc metadata).
- `OOB_WRITE` — out-of-bounds **write** that doesn't cleanly fit
  HEAP_OVERFLOW or STACK_OVERFLOW (e.g. global, mmap'd, JS heap,
  GPU buffer, IPC shared memory).
- `OOB_READ` — out-of-bounds **read**. Includes info-leak primitives
  (use the `severity` field to tag disclosure-only cases).
- `UAF` — use-after-free. Pointer/Ref/raw* survives the object that
  backs it and is later dereferenced. Includes use-after-`Ref::clear()`,
  use-after-destructor, and use-after-`std::move`-into-sink.
- `DOUBLE_FREE` — same allocation released twice down two paths.
- `TYPE_CONFUSION` — pointer reinterpreted as the wrong concrete type
  (downcast without checking, vtable swap, union mis-tag) leading to
  out-of-bounds field access or vtable hijack.
- `RACE_TO_TYPE_CONFUSION` — a thread observes an object mid-swap
  (two-phase init, dynamic-cast retire) and operates on it as the
  wrong type. Distinct from RACE_TO_UAF: object is alive, but the
  observed vtable/tag is incoherent with the field layout.
- `INT_OVERFLOW_TO_OOB` — integer overflow, underflow, signedness
  flip, or truncation in a size/length/offset/index/allocation-count
  computation that downstream feeds an OOB read or write. Use this
  class regardless of overflow vs underflow direction.
- `UNINIT_READ` — read of uninitialized stack/heap memory whose value
  reaches an attacker-observable channel or a security decision.
- `RACE_TO_OOB` — TOCTOU on a length/offset/bounds check that turns
  into OOB on the racing thread.
- `RACE_TO_UAF` — TOCTOU on a lifetime check (refcount, alive-flag,
  cancel-flag) that turns into UAF on the racing thread.
- `ARBITRARY_RW` — full attacker-controlled read or write primitive
  (address + value both attacker-influenced). Reserve for actual R/W
  primitives, not "could escalate to" cases.

### Severity precedence (when multiple classes plausibly apply)

```
HEAP_OVERFLOW ≈ STACK_OVERFLOW > OOB_WRITE > UAF > ARBITRARY_RW
              > TYPE_CONFUSION > RACE_TO_TYPE_CONFUSION
              > OOB_READ > INT_OVERFLOW_TO_OOB > UNINIT_READ
              > RACE_TO_OOB > RACE_TO_UAF > DOUBLE_FREE > n/a
```

When unsure, prefer the class that names the **sink** (write/read/free),
not the class that names the **upstream cause** (e.g. an integer
overflow that drives a heap write is `HEAP_OVERFLOW`, not
`INT_OVERFLOW_TO_OOB` — only use INT_OVERFLOW_TO_OOB when the sink
itself isn't reached but the arithmetic is the primitive bug).
