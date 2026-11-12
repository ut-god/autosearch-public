---
name: webkit-type-confusion-audit
description: Deep audit playbook for TYPE_CONFUSION and RACE_TO_TYPE_CONFUSION bugs in WebKit. Consult when the target method performs a downcast (jsCast, jsDynamicCast, static_cast across hierarchies), reads vtable / Structure / type-tag, decodes a tagged union / variant, casts an IPC-decoded value, or operates on a JSObject through an assumed concrete type. Returns the unchecked cast site and the missing inherits<> / type() check.
---

# WebKit Type Confusion Audit

Type confusion happens when a pointer is reinterpreted as the wrong
concrete type. The result is field accesses or vtable dispatches at
the wrong offsets / addresses — often an immediate `ARBITRARY_RW`
primitive in JSC contexts.

## 1. When this skill applies

Consult when the method contains:
- `jsCast` / `jsDynamicCast` / `jsDowncast` / `static_cast` across
  class hierarchies
- `structureID()` / `type()` / `classInfo()` reads followed by typed
  access
- `WTF::Variant` / `std::variant` / `WTF::Holds` dispatch without
  prior tag check
- `IPC::Decoder` reading a `Variant` / union-like type
- WebIDL conversion (`convert<IDLType>`) followed by typed use
- `JSCell` / `JSObject` access via raw butterfly / inline storage
- `ArrayBufferView` / `TypedArray` access via offset + length
- Plugin / NPAPI / extension dispatch through a generic handle
- JIT compilation (DFG/FTL/B3) — speculated types, CheckStructure,
  AI type predictions
- Structure transitions — cached offsets, watchpoints, polyProto
- DOM hierarchy casts — `downcast<>`, `dynamicDowncast<>`, `is<>`
- IndexingType — Contiguous vs ArrayStorage, TypedArray view types
- Wasm signatures — call_indirect, table.set, TypeIndex validation
- IPC Variant decode — `std::get` vs `std::get_if`, variant tag safety

## 2. The 11-question checklist

Answer ALL questions that match the triggers in Section 1.

### Q1. Cast preconditions

For every `jsCast<DerivedType*>(value)`:
- Is `value.inherits<DerivedType>(vm)` checked first?
- `jsCast` asserts in DEBUG, release-undefined-behavior in RELEASE
- `jsDynamicCast` returns null on mismatch and is the safe variant

```cpp
// ❌ release UB if value is not actually a DerivedType
auto* derived = jsCast<DerivedType*>(value);
derived->method();

// ✅ explicit check
if (!value.inherits<DerivedType>(vm))
    return scope.throwTypeError(...);
auto* derived = jsCast<DerivedType*>(value);

// ✅ alternative — null-safe cast
if (auto* derived = jsDynamicCast<DerivedType*>(value))
    derived->method();
```

For C++ `static_cast` across hierarchies:
- The base class must have a discriminator (`type()`, RTTI tag,
  custom enum)
- That discriminator must be checked on the SAME path

### Q2. GC / side-effect re-fetching

Any operation that can run JS, allocate, or trigger GC may invalidate
a previously-validated cast:
- `vm.heap.collectAsync()`, any `JSC::call()` / `JSC::construct()`
- Custom getter / setter execution (Proxy, accessor)
- `defineProperty`, `delete`, `[[Set]]` on a Proxy target
- Allocation paths that may garbage-collect (`JSObject::create*`)

After such a side-effect, the previously-cast pointer may now point
to a different type (Structure transition) or a different object
(GC moved cells in a generational collector). Re-validate or re-fetch.

### Q3. Structure / vtable assumptions

JSC's `JSCell` has a `Structure` pointer. If the Structure changes
(transition), prior assumptions about field layout are wrong.

- After any Structure-changing operation (`put`, `delete`,
  `defineProperty`), any cached field-offset is invalid
- Polymorphic inline caches must invalidate on structure transition
- `JSObject::butterfly()` layout depends on `IndexingType`; assuming
  `Contiguous` when the storage is `ArrayStorage` corrupts
- WebAssembly function signature index → wrong wasm function pointer
  on swap

### Q4. IPC / Variant decode safety

```cpp
// ❌ decoded variant without tag validation
Variant<A, B> v;
if (!decoder.decode(v))
    return false;
auto& a = std::get<A>(v);  // UB if v actually held B

// ✅
if (auto* a = std::get_if<A>(&v))
    handleA(*a);
```

The IPC decoder validates tags by default; bypassing or assuming the
decoded type is a TC primitive. Look for `decoder.decode<UnionT>(...)`
followed by direct `get<>` rather than `holds_alternative` / `get_if`.

### Q5. Race-to-type-confusion

If two threads can observe an object mid-Structure-transition:
- Thread A: starts cast based on Structure S1
- Thread B: transitions object to Structure S2
- Thread A: completes typed access using S1 layout, but storage is now S2

This is `RACE_TO_TYPE_CONFUSION` (object alive, but observed type
incoherent). Distinct from `RACE_TO_UAF` (object actually freed).

WebKit canonical sites:
- Worker → main-thread: shared `JSValue` accessed without barrier
- Compositor reading GraphicsContext state mid-mutation
- WebAssembly tier-up: function pointer swap mid-call

### Q6. JIT type speculation failure? (23 bugs in 5yr)

- Does DFG AI predict a type (SpecInt32, SpecString, SpecObject) and
  emit unchecked code for that assumption?
- Does FTL lower a CheckStructure to a specific StructureID that could
  change between compile and execute?
- Can a prototype chain mutation invalidate an inlined property access?
- Does CompareLessEq/CompareStrictEq optimize away a branch based on
  AI type prediction?

Grep: `SpeculatedType`, `CheckStructure`, `abstractValue`, `prediction`,
`AI::filter` in DFG/FTL.

### Q7. Structure transition invalidation? (25 bugs in 5yr)

- After defineProperty/put/delete, are cached field offsets
  re-validated?
- Is a Structure watchpoint properly fired when a transition occurs?
- Can a polyProto transition invalidate a cached prototype access?
- Is StructureID decoded/validated after a potential transition point?

Grep: `structureID`, `Structure::transition`, `polyProto`,
`watchpointFire`, `ObjectConditionSet`.

### Q8. Unchecked DOM/WebCore downcast? (101 bugs in 5yr)

- Is `downcast<DerivedType>` used without prior `is<DerivedType>`
  check?
- Is `dynamicDowncast` return value used without null check?
- Could the node/element type change between the check and the use
  (reentrancy)?
- Does RELEASE_ASSERT type check exist (commit 105163950fa3 added
  this on Intel)?

Grep: `downcast<`, `dynamicDowncast<`, `is<`,
`RELEASE_ASSERT.*is<` in target file.

### Q9. IndexingType confusion? (implicit in JIT bugs)

- Does the code assume Contiguous indexing but the array could be
  ArrayStorage?
- Does a TypedArray access assume Int32Array but the view could be
  Float64Array?
- Is the IndexingType checked before accessing the Butterfly?

Grep: `indexingType()`, `hasContiguous`, `hasArrayStorage`,
`Butterfly::indexingPayload`.

### Q10. Wasm type/signature confusion? (implicit in wasm bugs)

- Is a Wasm function call validated against the expected signature?
- Can table.set followed by call_indirect invoke a function with
  wrong signature?
- Is the Wasm type section properly validated before use?

Grep: `TypeIndex`, `SignatureIndex`, `call_indirect`, `table.set`
in JSC wasm/.

### Q11. IPC/Variant decode type safety? (1+ bugs in 5yr)

- After `decoder.decode<Variant<A,B>>`, is the active alternative
  checked before `get<A>`?
- Is `std::get_if` / `holds_alternative` used instead of raw
  `std::get`?
- Can a compromised process send a variant with an out-of-range
  type index?

Grep: `std::get<`, `std::get_if`, `holds_alternative`, `switchOn`,
`Variant` in IPC code.

## 3. CLAIM extraction

- `unchecked_op.file:line` — the cast or typed-access line
- `missing_check.file:line` — where `inherits<>` / `dynamicCast` /
  tag-check should be inserted
- `bug_class` — `TYPE_CONFUSION` (single-thread) or
  `RACE_TO_TYPE_CONFUSION`
- `patch_counterfactual` — replace `jsCast` with `jsDynamicCast` +
  nullcheck, OR add `inherits<>` guard, OR switch to `holds_alternative`
  + `get_if` for variants

## 4. Reference materials

Read these from the same directory if you need depth:

- `tc-pattern-catalog.md` — the 10-pattern taxonomy derived from
  5 years (2492 commits, 254 classified) of WebKit type confusion
  history. Each pattern has shape, trigger, sink, escalation,
  frequency, grep anchors, canonical code, and exemplar commits.
- `jsc-cast-hierarchy.md` — JSCell type tree, cast mechanisms table
  (jsCast/jsDynamicCast/dynamicDowncast/downcast safety), Structure
  and StructureID encoding, IndexingType enum with Butterfly layout,
  3 canonical "casts go wrong" scenarios.
- `jit-speculation-patterns.md` — DFG/FTL speculation pipeline,
  SpeculatedType primer, AbstractValue anatomy, 5 dangerous
  speculation-failure scenarios, CheckStructure placement patterns,
  Butterfly layout assumptions, audit anchors table.

## 5. What this skill won't help with

- Pure UAF (object actually freed) → `webkit-uaf-audit`
- Pure OOB at the cast site without type involvement →
  `webkit-bounds-audit`
- Integer overflow into a type-tag → `webkit-int-overflow-audit`
  for the arithmetic; this skill if the resulting tag is bypassed

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
