# Escalation Chains to ARBITRARY_RW

How primitive bugs escalate to full attacker-controlled read/write.
Each chain shows the steps and which mitigations block each step.

## Chain 1: Type Confusion → fakeobj/addrof → ARBITRARY_RW

1. **Type confusion** in JSC (e.g., JIT speculation failure, structure
   mismatch)
2. Confused type gives **addrof** (leak object address) and **fakeobj**
   (create fake JSObject at attacker address)
3. Fake JSObject with crafted Butterfly pointer → **relative OOB R/W**
   within Gigacage
4. Use OOB to corrupt a TypedArray's backing pointer → **cage escape**
   → arbitrary R/W

**Mitigations blocking each step:**
- Step 2: StructureID entropy (forging StructureID for fakeobj)
- Step 3: Gigacage (OOB confined to cage)
- Step 4: CagedBarrierPtr (backing pointer validated against cage)

## Chain 2: UAF → type confusion → ARBITRARY_RW

1. **Use-after-free** of a JSCell
2. Heap spray reclaims freed memory with a **different-type** object
3. Old pointer now points to wrong-type → **type confusion**
4. Continue as Chain 1 (fakeobj/addrof)

**Mitigations blocking each step:**
- Step 2: TZone/IsoHeap (freed cell only replaced by same type)
- Step 2: MTE (tag mismatch on reuse)
- Steps 3–4: Same as Chain 1

## Chain 3: OOB Write → function pointer overwrite → code exec

1. **Heap overflow** or **OOB write** with attacker-controlled
   offset+value
2. Overwrite a C++ vtable pointer or function pointer in adjacent
   memory
3. Trigger virtual call → **hijacked control flow**

**Mitigations blocking each step:**
- Step 1: Gigacage (if OOB is in caged buffer, can't reach C++ heap)
- Step 2: PAC (function pointer is signed, overwritten value won't
  authenticate)
- Step 3: CFI (indirect call target must match expected type)

## Chain 4: JIT bug → shellcode → code exec

1. **JIT compiler bug** emits wrong machine code (e.g., missing bounds
   check)
2. Wrong code gives attacker a memory R/W primitive
3. Attacker writes shellcode to JIT region
4. Jump to shellcode → **arbitrary code execution**

**Mitigations blocking each step:**
- Step 3: W^X (JIT pages are RX, not RWX)
- Step 3: JITCage (writes to JIT region require `performJITMemcpy`)
- Step 4: PAC (JIT entry points are signed)

## Chain 5: Renderer compromise → sandbox escape

1. Achieve ARBITRARY_RW in renderer via any chain above
2. Exploit IPC handler bug in privileged process (UI process, GPU
   process)
3. Break out of sandbox

**Mitigations blocking each step:**
- Step 2: IPC validation, process isolation
- Step 3: Sandbox policy (syscall filter, file access restrictions)

## Quick reference: which mitigations matter for which primitive

| Primitive Bug | Gigacage | JITCage | StructureID | PAC | TZone | MTE |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| UAF (JSCell) | — | — | — | — | ✅ blocks | ✅ blocks |
| UAF (C++ obj) | — | — | — | ✅ blocks vtable | ✅ blocks | ✅ blocks |
| OOB (caged buf) | ✅ confines | — | — | — | — | — |
| OOB (C++ heap) | — | — | — | ✅ blocks fptr | — | — |
| Type confusion | — | — | ✅ blocks fakeobj | — | — | — |
| JIT miscompile | — | ✅ blocks write | — | ✅ blocks entry | — | — |

## When in doubt

If you cannot map a bug to one of these chains within 60 seconds,
flag it for deeper analysis. Bugs whose escalation path is unclear
have historically been underrated and later exploited.
