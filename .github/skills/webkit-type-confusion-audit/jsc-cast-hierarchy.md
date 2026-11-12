# JSC Cast Hierarchy & Type System

Reference for the auditor. Consult when classifying type-safety of
casts and structure accesses during the SKILL.md checklist.

## JSCell type hierarchy

```
HeapCell
 └─ JSCell                      ← base of every GC-managed JS object
     ├─ JSObject                ← adds Butterfly (property/element storage)
     │   ├─ JSObjectWithButterfly
     │   │   ├─ JSFinalObject   ← sealed layout; cannot be subclassed in C++
     │   │   └─ JSNonFinalObject← extensible base
     │   │       ├─ JSArray
     │   │       ├─ JSCallee
     │   │       │   └─ JSFunction
     │   │       ├─ JSGlobalObject
     │   │       ├─ JSProxy
     │   │       └─ ...
     │   └─ (typed array views, RegExp, etc.)
     ├─ JSString
     ├─ Symbol
     └─ HeapBigInt
```

Every `JSCell` carries a `StructureID` in its header.
`Structure` holds the `ClassInfo*` pointer that the cast helpers inspect.

## Cast mechanisms

| Function | Checks type? | Returns | Safe? |
|---|:---:|---|:---:|
| `uncheckedDowncast<T>(v)` | DEBUG only (`ASSERT_WITH_SECURITY_IMPLICATION`) | `T&` / `T*` | ❌ Release UB |
| `downcast<T>(v)` | Yes (`RELEASE_ASSERT`) | `T&` / `T*` | ✅ Crashes on mismatch |
| `dynamicDowncast<T>(v)` | Yes (runtime `is<T>`) | `T*` or `nullptr` | ✅ |
| `is<T>(v)` / `inherits<T>()` | Yes | `bool` | ✅ (for guarding uncheckedDowncast) |
| `static_cast<T*>(v)` | No | `T*` | ❌ Always |

### Legacy names (pre-2023 code & comments)

| Legacy name | Current equivalent | Notes |
|---|---|---|
| `jsCast<T*>(v)` | `uncheckedDowncast<T>(v)` | Still referenced in DFG node `CheckJSCast`; same ASSERT-only semantics |
| `jsDynamicCast<T*>(v)` | `dynamicDowncast<T>(v)` | Runtime-checked; returns nullptr on failure |

### How `is<T>` works

```cpp
// JSCell::inherits<T>() → JSCastingHelpers::inherits<T>(this)
//   → classInfo()->isSubClassOf(T::info())
// classInfo() = structure()->classInfoForCells()
```

The check walks the `ClassInfo` parent chain. Cost is O(depth).

### What to flag

- `uncheckedDowncast` (or old `jsCast`) without a guarding `is<T>` /
  `inherits<T>` check — direct type confusion in release builds.
- `downcast` used on data derived from untrusted input without prior
  validation — crash is better than UB, but still a DoS.
- Any bare `static_cast<DerivedJSType*>(cell)` — always a bug unless
  the caller is compiler-generated code that already proved the type.

## Structure and StructureID

A `Structure` (`Source/JavaScriptCore/runtime/Structure.h`) encodes
everything the runtime needs to interpret a `JSCell`'s memory layout:

| Field | What it means |
|---|---|
| `m_classInfo` | Points to the `ClassInfo` vtable descriptor; used by `inherits()` |
| `m_blob` (TypeInfoBlob) | Packs `JSType`, `InlineTypeFlags`, indexing mode history |
| `m_inlineCapacity` | Number of property slots embedded in the object (not in Butterfly) |
| `m_propertyTableUnsafe` | Hash-map of property names → offsets |
| `m_prototype` | Prototype object pointer |
| `m_realm` | The global object / realm this structure belongs to |
| `m_transitionOffset` / `m_maxOffset` | Current and max property slot offsets |
| `m_cachedPrototypeChain` | Cached prototype chain for fast `instanceof` |
| `m_previousOrRareData` | Link to previous Structure (transition chain) or rare data |

### StructureID encoding (64-bit)

```
StructureID = uint32_t
  bits = reinterpret_cast<uintptr_t>(structure_ptr)   // lower 32 bits
  decode: reinterpret_cast<Structure*>(bits + structureIDBase())
```

- Structures live in a reserved VM region (`structureHeapAddressSize`,
  up to 4 GB on desktop). Only the low 32 bits vary → the ID is
  essentially a compressed pointer.
- `nukedStructureIDBit` (bit 0) marks a cell as "nuked" during GC;
  must be stripped via `decontaminate()` before decoding.
- `tryDecode()` validates the address falls within the structure heap.

### Structure transitions

When a property is added to an object:

1. The runtime looks up an existing transition from the current
   Structure for the new property name.
2. If none exists, a **new Structure** is allocated and linked as a
   transition from the old one.
3. The object's `StructureID` is updated atomically.

**Audit implication:** code that caches a `Structure*` or
`StructureID` and later uses it without re-validation is vulnerable
to TOCTOU if a side-effect (GC, proxy trap, getter) triggers a
structure transition in between.

## IndexingType enum

Defined in `Source/JavaScriptCore/runtime/IndexingType.h`. The
IndexingType is an 8-bit field packed into the cell header (via
Structure's `m_blob`).

```
Bit layout of IndexingTypeAndMisc:
  [0]   IsArray
  [1-3] Shape (enumerated, not bit-flags)
  [4]   CopyOnWrite
  [5]   MayHaveIndexedAccessors
  [6-7] Cell lock bits
```

| Shape constant | Value | Butterfly element layout |
|---|:---:|---|
| `NoIndexingShape` | 0x00 | No indexed storage |
| `UndecidedShape` | 0x02 | Empty array; shape chosen on first store |
| `Int32Shape` | 0x04 | Contiguous `int32_t` (NaN-boxed JSValues with int tag) |
| `DoubleShape` | 0x06 | Contiguous **raw** `double` (no tagging) |
| `ContiguousShape` | 0x08 | Contiguous NaN-boxed `JSValue` (any type) |
| `ArrayStorageShape` | 0x0A | Sparse; `ArrayStorage` header + vector |
| `SlowPutArrayStorageShape` | 0x0C | Like ArrayStorage but with indexed accessors on prototype |

### Why confusing IndexingTypes is dangerous

Each shape has a **different Butterfly memory layout**:

- `Int32Shape` / `ContiguousShape`: elements are 8-byte NaN-boxed
  `JSValue` slots at `butterfly->contiguous()[i]`.
- `DoubleShape`: elements are 8-byte **raw doubles** — not tagged.
  Reading a `DoubleShape` slot as a `JSValue` yields a
  pointer-forgery primitive if the attacker controls the double.
- `ArrayStorageShape`: has a `ArrayStorage` header (length, vector
  length, sparse map pointer) before the element vector.

If the JIT or runtime treats a `DoubleShape` array as
`ContiguousShape` (or vice-versa), every element read/write is a
type confusion on the **value representation**, not just the object
type.

## When casts go wrong — canonical scenarios

### 1. uncheckedDowncast without type guard (direct TC)

```cpp
// ❌ Attacker controls callFrame; object may not be JSArray
JSArray* array = uncheckedDowncast<JSArray>(callFrame->argument(0));
array->pushInline(vm, value);  // interprets Butterfly as JSArray layout

// ✅ Check first
auto* obj = callFrame->argument(0).getObject();
auto* array = dynamicDowncast<JSArray>(obj);
if (!array)
    return throwTypeError(globalObject, scope, "not an array"_s);
```

### 2. Structure transition between check and use (TOCTOU)

```cpp
// ❌ Side-effect invalidates the structure we just checked
Structure* s = obj->structure();
if (s == expectedStructure) {
    // A getter / Proxy trap / GC callback fires here and transitions
    // obj to a new structure with different layout.
    doSomethingAssumingStructure(obj, s);  // stale structure → TC
}

// ✅ Use a watchpoint or re-check after any call that may have
// side-effects:
if (obj->structure() != expectedStructure)
    return slowPath(obj);
```

### 3. GC / side-effect invalidates prior type validation

```cpp
// ❌ GC between validation and use
JSCell* cell = ...;
ASSERT(cell->inherits<JSObject>());
// ... allocate something (may trigger GC, which may finalize `cell`)
JSObject* obj = uncheckedDowncast<JSObject>(cell);
obj->putDirect(vm, name, value);  // UAF or wrong-type access

// ✅ Protect the cell across allocation
auto protectedCell = Strong<JSCell>(vm, cell);
// ... allocate ...
if (auto* obj = dynamicDowncast<JSObject>(protectedCell.get()))
    obj->putDirect(vm, name, value);
```

## When in doubt

If a cast is not obviously guarded by a preceding `is<T>` /
`dynamicDowncast` on the same control-flow path — with no
intervening calls that could trigger GC or side-effects — flag it
as audit-worthy. Historical JSC type confusions cluster around
exactly these patterns.
