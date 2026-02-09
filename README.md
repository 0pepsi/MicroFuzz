# microfuzz

> **Engine-semantic fuzzer for mQuickJS**  
> In-process • deterministic • grammar-aware • GC-aware • source + bytecode

---

## Overview

**microfuzz** is a custom fuzzer purpose-built for **mQuickJS**.  
It is designed around the engine’s *actual internal invariants*, *trust boundaries*, and *failure modes*, rather than generic compiler edge coverage.

> ⚠️ **Status**: The fuzzer has lots of problems in the meatime, working to fix them. 
---

## Why microfuzz?

mQuickJS has several properties that fundamentally change its attack surface:

| Property | Implication |
|--------|-------------|
| Single contiguous memory region | Heap/stack collisions are catastrophic |
| Bump allocator + mark-compact GC | All heap pointers invalidate after GC |
| No AST | Parser emits bytecode directly |
| Manual stack & frame layout | Frame offsets are security-critical |
| Unvalidated bytecode loading (`-b`) | Hard trust boundary violation |

---

## Threat Model

| Boundary | Assumed Trust | Reality |
|--------|--------------|---------|
| JS source → parser | Untrusted | Emits bytecode directly |
| Bytecode → interpreter | Trusted | **Not validated** |
| Runtime type tags | Correct | Forgeable via bytecode |
| GC compaction | Exhaustive | Missed pointer = UAF |
| Stack/frame offsets | In-range | Many unchecked |

microfuzz is designed to **cross these boundaries deliberately**.

---

## Engine Internals (Target Model)

### Memory Layout (Single Region)

```
High addresses
┌──────────────────────────┐
│   JSContext + metadata   │
├──────────────────────────┤
│        Heap (↑)          │
│  objects / strings / bc  │
├──────────────────────────┤
│        FREE SPACE        │
├──────────────────────────┤
│        Stack (↓)         │
│  values / frames / ops   │
└──────────────────────────┘
Low addresses
```

**Invariant**: `heap_free < stack_bottom`  
Violations are fatal.

---

### Value Representation (`JSValue`)

| Tag | Meaning |
|---|---|
| `0` | 31-bit signed int |
| `01` | Heap pointer |
| `101` | Short float |
| `0x03` | Boolean |
| `0x07` | Null |
| `0x0B` | Undefined |
| `0x0F` | Exception |
| `0x13` | Short function |
| `0x1B` | Single-char string |

---

### GC Model

- **Mark-compact**, not mark-sweep
- All heap pointers move during compaction
- Engine relies on `SAVE()` / `RESTORE()` to survive GC

> Missing *one* pointer update = dangling reference

---

## Coverage Model

microfuzz injects **engine-semantic coverage**, not compiler edges.

### Coverage Bitmap

- Shared memory
- 64 KB
- Bucketed counters (AFL-style)

---

### Coverage Classes

| Class | Purpose |
|----|--------|
| `OPCODE_COV` | Track executed bytecodes |
| `TYPE_COV` | Runtime type combinations |
| `CLASS_COV` | Object / function dispatch |
| `PARSE_COV` | Grammar production coverage |
| `GC_COV` | GC phase execution |
| `EXC_COV` | Exception-only paths |

---

### Example: Opcode Coverage

```c
#define OPCODE_COV(op) \
  __mqjs_cov_map[(0x1000 + (op)) % COV_MAP_SIZE]++
```

---

## Fuzzer Architecture

```
┌─────────────────────────────────────────┐
│              microfuzz                  │
│                                         │
│  ┌───────────┐   ┌─────────────────┐   │
│  │ Corpus    │◄─►│ Coverage Map    │   │
│  │ Manager   │   │ (64KB mmap)     │   │
│  └─────┬─────┘   └────────┬────────┘   │
│        │                  │            │
│  ┌─────▼──────────────────▼────────┐   │
│  │         Execution Engine         │   │
│  │  JS_NewContext / JS_Eval         │   │
│  │  Deterministic reset             │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │        Mutator Engine            │   │
│  │  Grammar-aware + bytecode-aware  │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

---

## Execution Model

```c
for (;;) {
    input = mutate(corpus_pick());
    memset(cov_map, 0, COV_SIZE);

    memset(mem_buf, 0, MEM_SIZE);
    ctx = JS_NewContext(mem_buf, MEM_SIZE, &stdlib);

    JS_SetRandomSeed(ctx, 0);
    JS_SetInterruptHandler(ctx, opcode_budget);

    JS_Eval(ctx, input, len, "<fuzz>", 0);
    JS_FreeContext(ctx);

    if (new_coverage(cov_map))
        corpus_add(input);
}
```

---

## Mutation Strategy

### Why Not Raw Bytes?

| Stage | Rejection Rate |
|----|----------------|
| Lexer | ~99% |
| Parser | ~99% of survivors |
| Interpreter | Near zero |

---

### Mutation Operators

yet to be announced still working on them
---

## Findings (Selected)

### 🧨 Out-of-Bounds Write: `js_reverse_val`

```c
tab[n - 1 - i] = tmp;
```

**Conditions**:
- `n` attacker-controlled
- No bounds validation
- Heap-relative OOB write

**Failure mode**:
- Memory corruption via unchecked length

---

### 🧨 Stack Corruption: `OP_put_arg`

```c
fp[FRAME_OFFSET_ARG0 + idx] = sp[0];
```

**Conditions**:
- `idx` read directly from bytecode
- No bounds check
- Reachable via `-b` bytecode path

**Failure mode**:
- Arbitrary frame overwrite
- Controlled write value
- Deterministic crash

---

## Results So Far

| Metric | Value |
|-----|------|
| Bugs found | 15+ |
| Bug classes | OOB, UAF, stack corruption |
| Inputs | JS source + bytecode |
| Reproducibility | 100% |

Some issues are exploitable with layout control and GC timing.

---

## Evolution

| Version | Focus |
|------|------|
| Early | Bytecode-only |
| Current | Full engine surface |

Expanding beyond bytecode **significantly increased bug yield**.

---


> _“Coverage that doesn’t encode meaning is noise.”_

