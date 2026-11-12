# WebKit Type Confusion Pattern Catalog

> **Methodology**: Bottom-up classification of 2492 type-confusion-related commits
> across WebKit (2021-01-01 → 2026-05-31). Each commit was tagged by keyword and
> diff-level structural analysis, then merged into deduplicated pattern buckets.
> The result is a taxonomy of **10 recurring type-confusion shapes** that account
> for 254 classified commits. The vast majority of the 2492 commits were SaferCPP
> downcast adoption refactoring (replacing `downcast<>` with `dynamicDowncast<>`,
> adding type checks, etc.) rather than actual bug fixes. This catalog replaces
> the earlier individual-CVE listing with a structural approach: audit for
> *patterns*, not individual bugs.

---

## Summary table

| ID | Pattern | 5yr Count |
|----|---------|:---------:|
| TC-DOWNCAST | Unchecked downcast failure | 144 |
| TC-STRUCTURE | Structure/StructureID confusion | 36 |
| TC-JIT | JIT type speculation failure | 31 |
| TC-GENERIC | Generic type mismatch | 18 |
| TC-EXPLICIT | Explicit type confusion | 8 |
| TC-STATE | State machine / enum confusion | 7 |
| TC-RACE | Race-to-type-confusion | 5 |
| TC-VARIANT | Variant/union tag mismatch | 2 |
| TC-WASM | Wasm type/signature confusion | 2 |
| TC-IPC | IPC decoded type mismatch | 1 |

---

## Pattern entries

---

### TC-DOWNCAST: Unchecked downcast failure
> **Note**: The TC-DOWNCAST count (144) includes both actual bugs AND preventive
> hardening (replacing `downcast<>` with `dynamicDowncast<>`). Roughly ~30 are
> actual crash/security fixes; ~114 are preventive hardening commits that
> proactively add runtime type checks before they can be exploited.

**Shape**: Code uses `jsCast<>`, `downcast<>`, or `static_cast<>` without runtime type verification; if the object is a different subclass, field access reads wrong offsets, corrupts state, or dereferences a vtable from the wrong class.
**Trigger**: A JS value, DOM node, or platform object arrives at a code path that unconditionally casts it to a specific subclass without an `inherits()`, `is<>()`, or `dynamicDowncast<>` guard.
**Sink**: The cast pointer is used to access subclass-specific fields at offsets that are only valid for the assumed type, or a virtual call dispatches through the wrong vtable.
**Escalation**: IP control (wrong vtable), arbitrary R/W (wrong field offsets), DoS (null deref on failed dynamicDowncast).
**5yr frequency**: 144 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/runtime/`, `Source/WebCore/dom/`, `Source/WebCore/accessibility/`, `Source/WebCore/platform/graphics/`, `Source/WebCore/bindings/js/`, `Source/WebCore/Modules/webaudio/`
**Grep anchors**:
```sh
rg "jsCast<" -n Source/JavaScriptCore/runtime
rg "downcast<" -n Source/WebCore/dom
rg "dynamicDowncast<" -n Source/WebCore/accessibility
rg "static_cast<.*\*>" -n Source/WebCore/platform/graphics
```
**Canonical code**:
```cpp
// ❌ bad — unchecked jsCast without type guard
JSValue val = callFrame->thisValue();
auto* obj = jsCast<JSMyObject*>(val);   // val might not be JSMyObject
obj->myField();                          // wrong offset → type confusion

// ✅ safe — use jsDynamicCast with null check
JSValue val = callFrame->thisValue();
auto* obj = jsDynamicCast<JSMyObject*>(val);
if (!obj)
    return throwTypeError(globalObject, scope);
obj->myField();
```
**Exemplar commits**:
- `2a042fede0e7` — jsCast in toPrimitive/toNumber without inherits check
- `43d73e7f6373` — dynamicDowncast null not checked in AXLogger
- `4be186fa2954` — jsCast during GC finalization with unreliable typeInfo
- `d7514794b61f` — unchecked jsCast<JSArray*> in AudioWorkletProcessor
- `e8ed2fcf97f0` — jsCast<JSDOMGlobalObject*> without type guard
- `f16677617fa2` — static_cast to wrong backend via ImageBufferBackendSharing
- `287f8c8f6baf` — uncheckedDowncast in generated toJSNewlyCreated
- `5295b8540e8e` — requiredListDowncast for CSS value list elements

---

### TC-STRUCTURE: Structure/StructureID confusion
**Shape**: JSC Structure assumptions are invalidated by transitions, polyProto, or concurrent access. Cached field offsets or StructureIDs become stale, causing the engine to interpret object memory using the wrong layout.
**Trigger**: A Structure transition (property addition, __proto__ mutation, custom-element definition) occurs after code has cached offsets or StructureIDs; or a StructureID is decoded incorrectly due to encoding bugs.
**Sink**: The stale Structure/offset is used to access a property at the wrong location, or a StructureID comparison succeeds incorrectly, bypassing a type guard.
**Escalation**: Arbitrary R/W (wrong offset), type confusion (wrong property types), IP control.
**5yr frequency**: 36 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/runtime/`, `Source/JavaScriptCore/dfg/`, `Source/JavaScriptCore/bytecode/`, `Source/JavaScriptCore/jit/`
**Grep anchors**:
```sh
rg "StructureID" -n Source/JavaScriptCore/runtime
rg "structureIDToStructure" -n Source/JavaScriptCore/runtime
rg "structureCacheCleared" -n Source/JavaScriptCore/dfg
rg "polyProto" -n Source/JavaScriptCore/runtime
```
**Canonical code**:
```cpp
// ❌ bad — cached StructureID compared without re-validating
if (object->structureID() == cachedStructureID) {
    // assume property at cachedOffset is correct type
    return object->getDirect(cachedOffset);
}

// ✅ safe — validate Structure pointer, not just ID; watch transitions
Structure* structure = object->structure();
if (structure != cachedStructure || structure->didTransition())
    return slowPath(object);
return object->getDirect(vm, structure->get(propertyName));
```
**Exemplar commits**:
- `1b11bc2ebce8` — custom element definition pollutes global structure
- `2ad8586458e4` — structureIDToStructure wrong decode on non-ADDRESS64
- `a512fe6e5cf8` — GetFromScope cached Structure* but compared StructureID
- `b7ecdfa767a3` — Object.assign stored meta-Structure's ID instead of object's
- `667a7374f1dd` — IC Presence condition missed getter redefinition
- `6d01e0a7489c` — DFG stale allocation structure without watching structureCacheCleared
- `8445e94cd3b6` — JSON.parse reuses cached transitions after __proto__ mutation
- `c888e174bc83` — StructureID encoding overhaul for hardening

---

### TC-JIT: JIT type speculation failure
**Shape**: DFG/FTL Abstract Interpreter predicts a wrong type for a value → emits unchecked machine code for that type → the code executes on a value of an unexpected type at runtime, reading memory at wrong offsets or applying wrong operations.
**Trigger**: The Abstract Interpreter (AI) produces an overly narrow or overly broad type prediction, constant-folds incorrectly, or fails to invalidate cached abstract values after graph mutations.
**Sink**: Generated machine code accesses a value assuming a type that does not match its runtime type, causing out-of-bounds access or wrong-type interpretation.
**Escalation**: Arbitrary R/W, IP control (JIT gadgets), type confusion.
**5yr frequency**: 31 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/dfg/`, `Source/JavaScriptCore/ftl/`, `Source/JavaScriptCore/bytecode/`
**Grep anchors**:
```sh
rg "AbstractValue" -n Source/JavaScriptCore/dfg
rg "SpecObjectOther|SpecBytecodeTop" -n Source/JavaScriptCore/bytecode
rg "validateAIState" -n Source/JavaScriptCore/dfg
rg "compileEnumeratorGetByVal" -n Source/JavaScriptCore/dfg
```
**Canonical code**:
```cpp
// ❌ bad — AI predicts SpecObjectOther but two iterator types share it
case MapIterator:
case SetIterator:
    // both predict SpecObjectOther, AI merges them, emits code for wrong one

// ✅ safe — use distinct SpecTypes for each iterator kind
case MapIterator:
    setResult(SpecMapIterator);   // unique prediction
case SetIterator:
    setResult(SpecSetIterator);
```
**Exemplar commits**:
- `045fd8ec9237` — JSMapIterator/JSSetIterator shared SpecObjectOther
- `291f0457787d` — constant folding treats top AbstractValue as empty constant
- `3af657fdb040` — CFA fails to clear values after graph packing
- `40c95aef90c7` — validateAIState queries AbstractValue from tuple node
- `67c8ea6bd1f0` — FTL masks signed instead of unsigned Atomics result
- `87e293ca831e` — DFG 32-bit compileEnumeratorGetByVal wrong edge type
- `90aa8070e1b6` — OSR availability wrong when local clobbered
- `ff7f706b1d90` — DFG AI too broad SpecBytecodeTop for ProxyObject GetInternalField

---

### TC-EXPLICIT: Explicit type confusion
**Shape**: A value conversion or type coercion function explicitly reinterprets data as the wrong type — wrong union branch, wrong enum-to-type mapping, or a missing type coercion step in generated code.
**Trigger**: A manual conversion function (e.g., `convertPathOperation`, `ConvertShapeValue`) receives a value of an unexpected variant or fails to apply a required type coercion.
**Sink**: The converted value is used with incorrect type assumptions, causing memory corruption or logic errors.
**Escalation**: Memory corruption, DoS, logic errors depending on context.
**5yr frequency**: 8 commits (2021–2026)
**Affected dirs**: `Source/WebCore/css/`, `Source/WebCore/rendering/`, `Source/WebGPU/WGSL/`
**Grep anchors**:
```sh
rg "convertPathOperation|ConvertShapeValue" -n Source/WebCore/css
rg "ConvertGridTrackSizeList" -n Source/WebCore/css
rg "applyValueContent" -n Source/WebCore/css
```
**Exemplar commits**:
- `067d7d9bd148` — applyValueContent
- `0875b595b40e` — ConvertShapeValue
- `1d37f3665114` — convertPathOperation
- `64b84dc3788d` — ConvertGridTrackSizeList
- `82a09825dd6e` — WGSL pointer rewriting erases type coercion

---

### TC-STATE: State machine / enum confusion
**Shape**: An enum or state variable holds a wrong value, causing dispatch to the wrong handler or creation of an object with the wrong configuration. The confusion is between valid enum values, not between types of objects.
**Trigger**: A function receives or stores the wrong enum variant — duplicate bit values, copy-paste of wrong constant, or stale cached state from a previous operation.
**Sink**: A switch/dispatch on the enum routes to the wrong handler, or a constructor creates an object with wrong configuration (e.g., wrong pixel format).
**Escalation**: Memory corruption (wrong buffer layout), logic errors, DoS.
**5yr frequency**: 7 commits (2021–2026)
**Affected dirs**: `Source/WebCore/platform/graphics/`, `Source/WebCore/layout/`, `Source/WebGPU/WGSL/`, `Source/WebCore/Modules/appbadge/`, `Source/WebCore/navigation/`
**Grep anchors**:
```sh
rg "InlineLevelBox::Type" -n Source/WebCore/layout
rg "BGRA\|kRGBA_8888" -n Source/WebCore/platform/graphics
rg "getAssertion.*Create\|Get" -n Source/WebCore/Modules
```
**Exemplar commits**:
- `447bcbf92118` — BGRA format set but kRGBA_8888 surface created
- `714cb095af54` — duplicate bit values in InlineLevelBox::Type
- `7dc1af69d5f2` — WGSL type checker assumes IdentifierExpression after bottom-type unification
- `80ecaf1c7301` — getAssertion passed Create instead of Get type
- `f64d31c61cfe` — dispatchNavigateEvent used stale m_loadType instead of parameter

---

### TC-RACE: Race-to-type-confusion
**Shape**: A concurrent Structure transition is observed mid-access by another thread. The reading thread sees a partially-updated Structure or StructureID, causing it to interpret the object's fields using the wrong layout.
**Trigger**: One thread transitions an object's Structure (adding properties, changing prototype) while another thread reads the StructureID or property offsets without proper synchronization.
**Sink**: The reading thread decodes a stale or mid-transition StructureID and accesses properties at wrong offsets.
**Escalation**: Arbitrary R/W, type confusion, IP control.
**5yr frequency**: 5 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/runtime/`, `Source/JavaScriptCore/dfg/`
**Grep anchors**:
```sh
rg "decontaminate" -n Source/JavaScriptCore/runtime
rg "StructureID::decode" -n Source/JavaScriptCore/runtime
rg "constant.*fold.*structure" -n Source/JavaScriptCore/dfg
```
**Exemplar commits**:
- `02b0bfc51d45` — StructureID::decode without decontaminate on concurrent read
- `64714692967a` — DFG constant-folds property using mid-transition structure

---

### TC-VARIANT: Variant/union tag mismatch
**Shape**: A tagged union, variant, or tuple is accessed via the wrong tag or index, retrieving data of the wrong type from the storage.
**Trigger**: A switch on a variant tag uses the wrong case, or a tuple accessor uses an incorrect index, causing the code to interpret the stored bits as the wrong type.
**Sink**: The wrongly-typed value is used in subsequent operations, causing memory corruption or logic errors.
**Escalation**: Type confusion, memory corruption, DoS.
**5yr frequency**: 2 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/dfg/`, `Source/JavaScriptCore/bytecode/`
**Grep anchors**:
```sh
rg "switchOnTupleAtIndex" -n Source/JavaScriptCore/dfg
rg "GetterSetter" -n Source/JavaScriptCore/bytecode
```
**Exemplar commits**:
- `a556285e269b` — switchOnTupleAtIndex implementation wrong
- `78c04663bf63` — Getter retrieves wrong pair type from cached data

---

### TC-WASM: Wasm type/signature confusion
**Shape**: WebAssembly type checking uses the wrong comparison operator or index scope, allowing a function reference or value of one type to be used where a different type is expected.
**Trigger**: A type check uses `==` instead of `isSubtype` for typed function references, or a recursion-group subtype check indexes into the wrong scope.
**Sink**: A function with the wrong signature is called, or a value of the wrong type is passed through a typed boundary.
**Escalation**: Type confusion in Wasm execution, potential arbitrary code execution.
**5yr frequency**: 2 commits (2021–2026)
**Affected dirs**: `Source/JavaScriptCore/wasm/`
**Grep anchors**:
```sh
rg "isSubtype\|funcref" -n Source/JavaScriptCore/wasm
rg "recursionGroup" -n Source/JavaScriptCore/wasm
```
**Exemplar commits**:
- `61e1a1710342` — tail call == instead of isSubtype for typed funcref
- `692b33ef1461` — recursion group subtype check uses wrong index scope

---

### TC-IPC: IPC decoded type mismatch
**Shape**: An IPC reply handler returns a value of the wrong type — e.g., a success type where an error type was expected, or vice versa — causing the receiver to misinterpret the payload.
**Trigger**: An error path in an async IPC reply constructs the reply with the success type constructor instead of `makeUnexpected`, or decodes the wrong variant from the wire.
**Sink**: The receiver interprets error data as success data (or vice versa), corrupting state or bypassing error handling.
**Escalation**: Logic errors, state corruption, potential security bypass.
**5yr frequency**: 1 commit (2021–2026)
**Affected dirs**: `Source/WebKit/`
**Grep anchors**:
```sh
rg "makeUnexpected\|asyncReply" -n Source/WebKit
```
**Exemplar commits**:
- `3a6dbc8aff5d` — async reply error returns success type instead of makeUnexpected

---

### TC-GENERIC: Generic type mismatch
> **Note**: TC-GENERIC is a catch-all bucket for type confusion commits that do
> not fit neatly into the other 9 patterns. These 18 commits need further
> individual review and may be reclassified as more data comes in or as new
> sub-patterns emerge with ≥ 3 exemplars.

**Shape**: A value of one type is used where a different type is expected, but the mechanism does not match any of the specific patterns above. This includes miscellaneous casting errors, wrong template instantiations, and ad-hoc type mismatches.
**Trigger**: Various — ad-hoc type errors that don't fit the other categories.
**Sink**: Type-dependent operations execute on wrongly-typed data.
**Escalation**: Varies by instance — from DoS to arbitrary R/W.
**5yr frequency**: 18 commits (2021–2026)
**Affected dirs**: Various
**Exemplar commits**: Pending individual review and reclassification.

---

## Adding new exemplars

When a new type confusion fix is committed to WebKit:

1. **Classify** — read the diff and determine which pattern (TC-DOWNCAST through
   TC-IPC) it matches. If it matches none, add it to TC-GENERIC for later review.
   If TC-GENERIC accumulates ≥ 3 structurally similar commits, consider splitting
   them into a new named pattern.
2. **Append** — add the commit hash and a 1-line description to the pattern's
   `Exemplar commits` list.
3. **Update the count** — increment the pattern's `5yr frequency` and the summary
   table count.
4. **Cross-check** — if the commit touches a directory not yet listed in
   `Affected dirs`, add it.

Patterns are intentionally coarse-grained (10 buckets for 254 commits). Resist
the urge to split a pattern unless the new sub-pattern has ≥ 3 exemplars with a
structurally distinct shape.
