# Security Audit: keccak_memory.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `keccak_memory.pil` gadget handles memory slice operations for the Keccak-f1600 permutation. It reads or writes 25 contiguous U64 values representing the Keccak state, using a multi-row computation with value shifting.

### Key Characteristics
- Multi-row operation: 25 rows per slice (one per state element)
- Two modes: read (with tag checking) and write (no errors possible)
- Values shifted diagonally to present all 25 values at the start row
- Tag error detection with early termination

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/keccak_memory.pil` | PIL constraint definitions (270 lines) |

---

## 3. Constraint Analysis

### 3.1 Lifecycle Constraints

**TRACE_CONTINUITY (line 94)**:
```
(1 - precomputed.first_row) * (1 - sel) * sel' = 0
```

**CTR_INIT (line 114)**:
```
(start_read + start_write) * (ctr - 1) = 0
```

**START_AFTER_LATCH (line 152)**:
```
sel' * (start_read' + start_write' - LATCH_CONDITION) = 0
```

**SEL_CTR_NON_ZERO (line 126)**:
```
ctr * ((1 - sel) * (1 - ctr_inv) + ctr_inv) - sel = 0
```
- `sel = 1` iff `ctr != 0`

### 3.2 Counter and Address Management

**CTR_INCREMENT (line 156)**:
```
sel * (1 - LATCH_CONDITION) * (ctr' - ctr - 1) = 0
```

**CTR_END (line 135)**:
```
sel * ((constants.AVM_KECCAKF1600_STATE_SIZE - ctr) * (ctr_end * (1 - state_size_min_ctr_inv) + state_size_min_ctr_inv) + ctr_end - 1) = 0
```
- `ctr_end = 1` iff `ctr = 25`

**MEM_ADDR_INCREMENT (line 177)**:
```
sel * (1 - LATCH_CONDITION) * (addr + 1 - addr') = 0
```

### 3.3 Read/Write Mode

**RW_READ_INIT (line 118)**:
```
start_read * rw = 0
```

**RW_WRITE_INIT (line 120)**:
```
start_write * (1 - rw) = 0
```

**RW_PROPAGATION (line 186)**:
```
(1 - LATCH_CONDITION) * (rw' - rw) = 0
```

### 3.4 Tag Error Handling

**SINGLE_TAG_ERROR (line 193)**:
```
sel * (TAG_MIN_U64 * ((1 - single_tag_error) * (1 - tag_min_u64_inv) + tag_min_u64_inv) - single_tag_error) = 0
```
- `single_tag_error = 1` iff `tag != U64`

**LAST (line 143)**:
```
last = 1 - (1 - ctr_end) * (1 - single_tag_error)
```
- Early termination on tag error

**NO_TAG_ERROR_ON_WRITE (line 166)**:
```
rw * single_tag_error = 0
```
- Writes cannot have tag errors

**TAG_ERROR_PROPAGATION (line 172)**:
```
(1 - LATCH_CONDITION) * (tag_error - tag_error') = 0
```

### 3.5 Value Shifting

**VAL01 through VAL24 (lines 196-242)**:
```
val[k] = (1 - LATCH_CONDITION) * val[k-1]'
```
- Values shift right going bottom-up
- At start row, all 25 values are available horizontally

### 3.6 Memory Integration

**SLICE_TO_MEM (line 244)**:
```
sel { clk, space_id, addr, val[0], tag, rw }
is memory.sel_keccak { memory.clk, memory.space_id, memory.address, memory.value, memory.tag, memory.rw };
```

---

## 4. Soundness Analysis

### 4.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Invalid counter start | CTR_INIT enforces ctr=1 | PROTECTED |
| Skip memory rows | CTR_INCREMENT + ctr_end | PROTECTED |
| Change mode mid-slice | RW_PROPAGATION | PROTECTED |
| Forge tag on write | NO_TAG_ERROR_ON_WRITE | PROTECTED |
| Truncate before 25 rows | CTR_END defines last properly | PROTECTED |
| Ghost row memory access | SEL_CTR_NON_ZERO guards sel | PROTECTED |

### 4.2 Illegal Memory Operation Prevention

The file includes a detailed proof (lines 252-269) showing that all memory operations are legitimate:

1. If `sel = 1`, then `ctr != 0` by `SEL_CTR_NON_ZERO`
2. Tracing back via `CTR_INCREMENT`, we eventually reach a row where `start_read = 1` or `start_write = 1`
3. At that row, `CTR_INIT` enforces `ctr = 1`
4. Counter cannot exceed 25 because `last` activates at `ctr = 25`

### 4.3 Value Shifting Correctness

The value shifting mechanism:
- At row with `ctr = 25`: `val[0]` = value from memory
- At row with `ctr = 24`: `val[0]` = previous value, `val[1]` = current value
- At row with `ctr = 1` (start): All 25 values in `val[0]..val[24]`

When `LATCH_CONDITION = 1`, the shift is zeroed, terminating the chain correctly.

### 4.4 Precondition

The gadget assumes `offset + 24 < 2^32` (slice fits in memory). This is the caller's responsibility.

---

## 5. Findings

### No Critical Vulnerabilities Found

The keccak_memory gadget is **SOUND**.

### INFO-1: Early Termination on Tag Error

When a tag error occurs during read, the computation terminates early with `last = 1`. The `tag_error` flag is propagated back to the start row for the caller to check.

### INFO-2: num_rounds Constraint

```
sel * (num_rounds - constants.AVM_KECCAKF1600_NUM_ROUNDS) = 0
```

This column is used by keccakf1600.pil to constrain the round count to 24 via the write lookup.

---

## 6. Conclusion

**Status**: SOUND

The keccak_memory gadget correctly implements memory slice operations for Keccak with:
- Proper counter management preventing row skipping
- Secure value shifting for horizontal access at start
- Tag error detection with early termination
- Mode propagation preventing read/write confusion

The constraint system is complete and no soundness vulnerabilities were identified.
