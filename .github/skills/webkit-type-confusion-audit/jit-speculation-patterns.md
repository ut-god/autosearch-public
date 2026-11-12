# DFG/FTL Type Speculation & Type Confusion Patterns

Reference for the auditor. Consult when evaluating JIT-related type
confusion risks during the SKILL.md checklist.

## How speculation works

The DFG/FTL compilation pipeline narrows types at each stage:

```
Baseline JIT profiling
  → ValueProfile at heap load sites records observed SpeculatedType
  → PredictionPropagationPhase seeds per-node type predictions
    → AbstractInterpreter refines AbstractValue (type ∩ structure ∩ arrayModes)
      → CheckStructure / CheckCell nodes inserted where assumptions need guarding
        → Type-specific lowering (e.g., Int32 add instead of generic ValueAdd)
          → If prediction is wrong at runtime → OSR exit back to baseline
```

Key files:

| Component | File |
|---|---|
| `SpeculatedType` bits | `bytecode/SpeculatedType.h` |
| `AbstractValue` | `dfg/DFGAbstractValue.h` |
| Prediction propagation | `dfg/DFGPredictionPropagationPhase.cpp` |
| Abstract interpreter | `dfg/DFGAbstractInterpreterInlines.h` |
| Check insertion | `dfg/DFGSpeculativeJIT.cpp` |
| ArrayMode | `dfg/DFGArrayMode.h` |

## SpeculatedType primer

`SpeculatedType` is a 64-bit bitmask. Each bit represents a
possible value kind:

| Type bits | Meaning |
|---|---|
| `SpecInt32Only` | `SpecBoolInt32 \| SpecNonBoolInt32` |
| `SpecDoubleReal` | IEEE-754 real (not NaN) double |
| `SpecDoubleNaN` | NaN double |
| `SpecString` | `SpecStringIdent \| SpecStringVar` |
| `SpecObject` | `SpecFinalObject \| SpecArray \| ...` (many sub-bits) |
| `SpecCell` | `SpecObject \| SpecString \| SpecSymbol \| SpecHeapBigInt \| ...` |

The DFG narrows `SpeculatedType` via `AbstractValue::filter()`.
Once narrowed, the compiler emits specialized machine code that
skips type checks — this is where TC bugs live.

## AbstractValue

Each DFG node has an `AbstractValue` that tracks what values it may
produce:

```cpp
struct AbstractValue {
    SpeculatedType m_type;              // bitmask of possible types
    StructureAbstractValue m_structure; // set of possible Structures
    ArrayModes m_arrayModes;            // bitmask of possible IndexingTypes
    JSValue m_value;                    // constant-folded value (if known)
};
```

`clobberStructures()` resets `m_structure` and `m_arrayModes` when
a side-effect may have changed object shapes. **Missing clobbers
are a primary source of TC.**

## When speculation fails — dangerous scenarios

### 1. AI predicts SpecInt32Only but value can be SpecDouble

```
Profile saw only int32 values at a load site.
DFG emits unboxing code that reads the payload as int32.
Attacker triggers the path with a double → reads double bits as int32.
If no OSR exit check guards the unboxing, this is a miscompilation.
```

**Audit anchor:** look for `SpecInt32Only` narrowing without a
`CheckInt32` or equivalent guard node.

### 2. AI folds comparison to constant based on type prediction

```
AI proves left is SpecString, right is SpecInt32Only.
CompareStrictEq can never be true (different types) → folded to false.
But if the type prediction was wrong (left can be int32 too),
the fold removes a branch that was security-relevant.
```

**Audit anchor:** `foldPathCondition`, constant-folding of
comparison nodes in `DFGAbstractInterpreter`.

### 3. Prototype chain invalidation not caught by watchpoint

```
DFG caches a property access assuming the prototype chain is stable.
A Proxy or custom setter mutates the prototype.
If the WatchpointSet is not properly hooked (or already invalidated
but the compiled code was not jettisoned), the cached access reads
from a stale offset → TC.
```

**Audit anchor:** `StructureChainInvalidation`,
`AdaptiveInferredPropertyValueStructure`, `CodeBlockJettisoning`
watchpoint kinds.

### 4. ObjectPropertyConditionSet not validated at compile time

```
DFG multi-access optimization builds an ObjectPropertyConditionSet
(e.g., "property X is absent on all prototypes up to Base").
If the set is not re-validated when installing the compiled code,
a race between compilation and installation can violate the
conditions → wrong property offset → TC.
```

**Audit anchor:** `ObjectPropertyConditionSet::isValid()`,
`generateConditionsForPropertySetterMiss()`.

### 5. Constructor call without `new` yields different object type

```
Typed array constructor called without `new` returns a different
type (or throws). If the DFG speculates that the result is always
a typed array and emits CheckStructure accordingly, calling without
`new` may produce an unexpected object that passes the structure
check (or the check is missing) → TC.
```

**Audit anchor:** `isConstructor`, `constructType`,
`callData.type != CallData::Type::None`.

## CheckStructure patterns

`CheckStructure` is the primary guard node in DFG/FTL. It verifies
an object's `StructureID` matches one of the expected `Structure*`
values before proceeding with specialized access.

```cpp
// Emitted as:
//   load obj->structureID
//   compare against expectedStructure(s)
//   if mismatch → OSR exit

// ❌ DFG emits CheckStructure for S1, but S1 transitions to S2
//    between compile and execute. No watchpoint installed.
//    → object passes install-time validation but fails at runtime
//      with a structure the compiled code wasn't prepared for.

// ✅ DFG must register a watchpoint on the structure's transition
//    set. If S1 transitions, the watchpoint fires, the CodeBlock is
//    jettisoned, and the code falls back to baseline.
```

### Structure check is only as good as its placement

If a `CheckStructure` guards node N, but node N+3 calls a function
that may trigger a structure transition on the same object, then
node N+4 is using a **stale** structure assumption:

```
N:   CheckStructure(obj, {S1})
N+1: GetByOffset(obj, offset_in_S1)    // safe
N+2: Call(someFunction, obj)            // may transition obj to S2
N+3: GetByOffset(obj, offset_in_S1)    // ❌ obj may now be S2
```

The abstract interpreter must `clobberStructures()` at N+2 and the
compiler must re-emit CheckStructure before N+3.

## Butterfly layout assumptions

The DFG inspects `ArrayMode` to decide how to access array elements.
Each `ArrayMode` implies a specific `IndexingType`, which in turn
implies a specific Butterfly memory layout:

| ArrayMode type | Butterfly element format | Access pattern |
|---|---|---|
| `Int32` | 8-byte NaN-boxed JSValues (int32 tag) | `butterfly->contiguous().at(i)` |
| `Double` | 8-byte **raw doubles** (no tag) | `butterfly->contiguousDouble().at(i)` |
| `Contiguous` | 8-byte NaN-boxed JSValues (any tag) | `butterfly->contiguous().at(i)` |
| `ArrayStorage` | `ArrayStorage` header + element vector | `butterfly->arrayStorage()->m_vector[i]` |

### The canonical Butterfly TC

```
DFG profiled the array as Int32Shape.
Emits direct load from butterfly->contiguous().at(i).
Attacker transitions the array to DoubleShape.
The load reads a raw double, but the compiler treats it as a
NaN-boxed JSValue → pointer forgery / info leak.
```

This is why `CheckStructure` must cover array accesses, and why
`ArrayMode` mismatches are a top-tier TC class.

### CopyOnWrite arrays

Arrays with `CopyOnWrite` flag use a `JSCellButterfly` whose
header includes a JSCell marker. Writing to a CoW array triggers
a copy. If the compiler emits a direct store without checking CoW
status, it corrupts the shared backing store.

## Common audit anchors

Grep for these identifiers when auditing DFG/FTL code:

| Identifier | Why it matters |
|---|---|
| `SpeculatedType` | Type prediction bitmask; over-narrow = TC |
| `AbstractValue` | Per-node type/structure envelope; missing filter = TC |
| `CheckStructure` | Primary runtime type guard; absent or stale = TC |
| `ArrayMode` | Encodes assumed IndexingType; wrong mode = Butterfly TC |
| `IndexingType` | Raw shape bits; see `IndexingType.h` |
| `OSRExit` | Bailout mechanism; missing exit = no safety net |
| `Watchpoint` / `WatchpointSet` | Invalidation hooks; unwatched transition = TOCTOU |
| `ObjectPropertyConditionSet` | Multi-property assumption bundle; unvalidated = TC |
| `clobberStructures` | AI side-effect handler; missing = stale AbstractValue |
| `StructureAbstractValue` | Tracked Structure set; wrong set = wrong offset |
| `arrayMode()` | Per-node array access mode; check it matches reality |
| `exitKind` | Why OSR exited; `BadType` exits indicate speculation failure |

## When in doubt

If a DFG optimization removes or weakens a type check, and you
cannot find a corresponding `CheckStructure`, `Watchpoint`, or
`OSRExit` path that would catch a mismatch at runtime — flag it.
JIT TC bugs arise precisely when the compiler "knows" a type but
reality disagrees.
