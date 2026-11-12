# Wasm Bounds Patterns

Out-of-bounds patterns specific to WebAssembly memory operations in JSC.

## Memory access tiers

| Tier | How bounds are checked | Risk |
|------|----------------------|------|
| LLInt | Explicit check in slow path | Check may miss last byte |
| IPInt | Inline check per opcode | 64-bit truncation, multi-memory index |
| BBQ | WASM_BOUNDS_CHECK node in Air | Codegen may use wrong size |
| OMG | B3 bounds check hoisting | Hoisted check may use stale base |
| Signaling | Guard page trap | Safe for in-bounds grow; no trap for 0-size memory |

## Common bug shapes

### 1. Last-byte omission
```cpp
// ❌ checks start but not start+accessSize-1
if (offset < memorySize)
    load(base + offset);  // 8-byte load at offset=memorySize-1 reads 7 OOB bytes

// ✅ checks full access range
if (offset + accessSize <= memorySize)
    load(base + offset);
```

### 2. Memory64 pointer truncation
```cpp
// ❌ 64-bit effective address truncated to 32-bit
uint32_t ea = static_cast<uint32_t>(offset64 + base64);  // high bits lost
if (ea < memorySize32) ...  // check passes on truncated value

// ✅ keep 64-bit throughout
uint64_t ea = offset64 + base64;
if (ea + accessSize > memorySize64) trap();
```

### 3. Multi-memory index confusion
```cpp
// ❌ wrong memory index used for bounds check
auto* memory = instance->memory(0);  // should be memory(memoryIndex)
if (offset < memory->size()) ...
```

### 4. Bounds check underflow (0-size memory)
```cpp
// ❌ memorySize - accessSize underflows when memorySize=0
if (offset <= memorySize - accessSize)  // underflow → huge value → check passes
    load(base + offset);

// ✅ rearrange to avoid underflow
if (offset + accessSize > memorySize) trap();
// or: if (memorySize < accessSize || offset > memorySize - accessSize) trap();
```

### 5. memory.copy / memory.fill length validation
```cpp
// ❌ checks dst but not dst+len
if (dst < memorySize && src < memorySize)
    memcpy(base+dst, base+src, len);  // len can go OOB

// ✅ check both ranges fully
if (dst + len > memorySize || src + len > memorySize) trap();
```

## Audit anchors

| Function | File | What to check |
|----------|------|---------------|
| `boundsCheck` | WasmBBQJIT.cpp, WasmOMGJIT.cpp | accessSize in check |
| `memoryFill` | WasmOperationsInlines.h | dst + len ≤ size |
| `memoryCopy` | WasmOperationsInlines.h | src+len, dst+len ≤ size |
| `atomicWait` | WasmSlowPaths.cpp | 64-bit EA not truncated |
| `atomicNotify` | WasmSlowPaths.cpp | same |
