# Deep Security Audit: data_copy.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL file: `pil/vm2/data_copy.pil` (405 lines)
- [x] Located dependencies: memory.pil, calldata.pil, gt.pil, precomputed.pil
- [x] Located callers: execution.pil (#[DISPATCH_TO_CD_COPY], #[DISPATCH_TO_RD_COPY])

### Phase 2: Understanding
- [x] Documented gadget purpose (CALLDATACOPY, RETURNDATACOPY)
- [x] Listed all witnesses (20+ columns)
- [x] Listed all constraints (25+ constraints)
- [x] Understood multi-row copy mechanism

### Phase 3: Soundness
- [x] Verified memory permutations
- [x] Analyzed bounds checking
- [x] Checked padding logic
- [x] Verified trace shape constraints

### Phase 4: Completeness
- [x] Reviewed error handling
- [x] Checked edge cases (zero copy, top-level)
- [x] Verified propagation constraints

### Phase 5: Integration
- [x] Verified execution dispatch
- [x] Checked memory interaction
- [x] Verified calldata interaction

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/data_copy.pil` | 405 | CALLDATACOPY and RETURNDATACOPY |

---

## 2. Gadget Architecture

### 2.1 Purpose

Handles two opcodes:
- **CALLDATACOPY**: Copy calldata from parent context to current context
- **RETURNDATACOPY**: Copy returndata from child context to current context

### 2.2 Invocation Patterns

**CD_COPY (from execution.pil):**
```pil
sel_exec_dispatch_calldata_copy {
    clk, parent_id, context_id,
    register[0], register[1], rop[2],
    parent_calldata_addr, parent_calldata_size, sel_opcode_error
} is data_copy.sel_cd_copy_start { ... };
```

**RD_COPY (from execution.pil):**
```pil
sel_exec_dispatch_returndata_copy {
    clk, last_child_id, context_id,
    register[0], register[1], rop[2],
    last_child_returndata_addr, last_child_returndata_size, sel_opcode_error
} is data_copy.sel_rd_copy_start { ... };
```

### 2.3 Multi-Row Structure

Each copy operation spans multiple rows (one per element):

```
| sel_start | copy_size | dst_addr | read_addr | value | padding |
|-----------|-----------|----------|-----------|-------|---------|
|     1     |     3     |    5     |    10     |  100  |    0    |  ← start
|     0     |     2     |    6     |    11     |  200  |    0    |
|     0     |     1     |    7     |    12     |  300  |    0    |  ← sel_end=1
```

### 2.4 Top-Level Special Case

For enqueued calls (top-level), `src_context_id = 0`. In this case:
- Read from `calldata` column instead of memory
- `is_top_level = 1`

---

## 3. Bounds Checking

### 3.1 Computing Data Index Upper Bound

```pil
// data_copy.pil:218-229
offset_plus_size = sel_start * (offset + copy_size);

#[OFFSET_PLUS_SIZE_IS_GT_DATA_SIZE]
sel_start { offset_plus_size, src_data_size, offset_plus_size_is_gt }
in gt.sel_others { ... };

// min(src_data_size, offset + copy_size)
data_index_upper_bound = sel_start * ((src_data_size - offset_plus_size) * offset_plus_size_is_gt + offset_plus_size);
```

**Analysis**: Computes `min(offset + copy_size, src_data_size)` to prevent reading beyond source data.

### 3.2 Memory Address Bounds

```pil
// data_copy.pil:252-264
read_addr_upper_bound = sel_start * (src_addr + data_index_upper_bound);
#[CHECK_SRC_ADDR_IN_RANGE]
sel_start { read_addr_upper_bound, mem_size, src_out_of_range_err }
in gt.sel_others { ... };

write_addr_upper_bound = sel_start * (dst_addr + copy_size);
#[CHECK_DST_ADDR_IN_RANGE]
sel_start { write_addr_upper_bound, mem_size, dst_out_of_range_err }
in gt.sel_others { ... };
```

**Analysis**: Checks both read and write address ranges against `AVM_MEMORY_SIZE`.

---

## 4. Error Handling

### 4.1 Consolidated Error

```pil
// data_copy.pil:268-269
err = 1 - (1 - dst_out_of_range_err) * (1 - src_out_of_range_err); // OR
```

### 4.2 Error Behavior

```pil
// data_copy.pil:294-295
#[END_ON_ERR]
sel_start * err * (sel_end - 1) = 0;
```

**Analysis**: If error, `sel_end = 1` immediately, preventing any copy operations.

---

## 5. Memory Operations

### 5.1 Memory Write (Permutation)

```pil
// data_copy.pil:338-341
#[MEM_WRITE]
sel_mem_write { clk, dst_context_id, dst_addr, value, precomputed.zero/*(FF)*/, sel_mem_write/*(write)*/ }
is
memory.sel_data_copy_write { memory.clk, memory.space_id, memory.address, memory.value, memory.tag, memory.rw };
```

**Uses `is` (permutation)**: Critical for preventing malicious memory writes.

### 5.2 Memory Read (Permutation)

```pil
// data_copy.pil:386-389
#[MEM_READ]
sel_mem_read { clk, src_context_id, read_addr, value, tag, precomputed.zero/*(read)*/ }
is
memory.sel_data_copy_read { ... };
```

**Uses `is` (permutation)**: Ensures legitimate memory reads only.

### 5.3 Calldata Read (Lookup)

```pil
// data_copy.pil:401-404
#[COL_READ]
cd_copy_col_read { read_addr_plus_one, dst_context_id, value }
in
calldata.sel { calldata.index, calldata.context_id, calldata.value };
```

**Uses `in` (lookup)**: Safe for read-only operation from calldata trace.

---

## 6. Padding Logic

### 6.1 Padding Condition

```pil
// data_copy.pil:354-358
pol commit padding;
padding * (1 - padding) = 0;
#[PADDING_CONDITION]
SEL_PERFORM_COPY * (reads_left * (padding * (1 - reads_left_inv) + reads_left_inv) - 1 + padding) = 0;
```

**Analysis**: `padding = 1` iff `reads_left = 0` (zero-check pattern).

### 6.2 Padding Propagation

```pil
// data_copy.pil:361-362
#[PADDING_PROPAGATION]
(1 - sel_end) * padding * (1 - padding') = 0;
```

**Analysis**: Once in padding, stay in padding until end.

### 6.3 Padding Value

```pil
// data_copy.pil:381-382
#[PAD_VALUE]
padding * value = 0;
```

**Analysis**: Padding rows write zero.

---

## 7. Trace Shape Constraints

### 7.1 Trace Continuity

```pil
// data_copy.pil:150-151
#[TRACE_CONTINUITY]
(1 - precomputed.first_row) * (1 - sel) * sel' = 0;
```

### 7.2 Computation Finish

```pil
// data_copy.pil:164-165
#[COMPUTATION_FINISH_AT_END]
sel * (1 - sel') * (1 - sel_end) = 0;
```

**Analysis**: Cannot stop mid-computation without `sel_end = 1`.

### 7.3 Start After Latch

```pil
// data_copy.pil:175-176
#[START_AFTER_LATCH]
sel' * (sel_start' - LATCH_CONDITION) = 0;
```

**Analysis**: New computation must start after previous ends.

---

## 8. Soundness Verification

### 8.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Malicious memory write | #[MEM_WRITE] permutation | PROTECTED |
| Malicious memory read | #[MEM_READ] permutation | PROTECTED |
| Out-of-bounds read | #[CHECK_SRC_ADDR_IN_RANGE] | PROTECTED |
| Out-of-bounds write | #[CHECK_DST_ADDR_IN_RANGE] | PROTECTED |
| Truncate computation | #[COMPUTATION_FINISH_AT_END] | PROTECTED |
| Insert extra rows | #[START_AFTER_LATCH] | PROTECTED |
| Read past source data | data_index_upper_bound min() | PROTECTED |
| Skip execution dispatch | Permutations for CD/RD start | PROTECTED |

### 8.2 Critical Security Properties

#### 8.2.1 Permutation for All Memory Operations

Both `#[MEM_WRITE]` and `#[MEM_READ]` use permutations (`is`), ensuring:
- Every memory operation in data_copy has corresponding memory trace entry
- No extra memory operations can be forged

#### 8.2.2 Bounds Checking via GT

Four GT lookups ensure:
1. `offset + copy_size` vs `src_data_size` (compute min)
2. `read_addr_upper_bound` vs `mem_size` (src range)
3. `write_addr_upper_bound` vs `mem_size` (dst range)
4. `data_index_upper_bound` vs `offset` (reads_left calculation)

#### 8.2.3 Top-Level Detection

```pil
#[TOP_LEVEL_COND]
sel_cd_copy * (src_context_id * (is_top_level * (1 - parent_id_inv) + parent_id_inv) - 1 + is_top_level) = 0;
```

Zero-check ensures `is_top_level = 1` iff `src_context_id = 0`.

---

## 9. Findings

### No Critical Vulnerabilities Found

The data_copy.pil gadget is **SOUND**.

### INFO-1: Dual Invocation Paths

The gadget supports both CALLDATACOPY and RETURNDATACOPY via separate start selectors (`sel_cd_copy_start`, `sel_rd_copy_start`), both dispatched via permutations from execution.

### INFO-2: Top-Level Calldata Special Case

For enqueued calls, calldata is read from the `calldata` column instead of memory. This is correctly detected via `is_top_level` zero-check on `src_context_id`.

### INFO-3: Padding Mechanism

When `reads_left = 0` but `copy_size > 0`, the gadget writes zeros. This handles cases where the requested copy extends beyond available data.

### INFO-4: Address Incrementing

```pil
#[INCR_WRITE_ADDR]
sel * (1 - sel_end) * (dst_addr' - dst_addr - 1) = 0;
```

Write addresses increment by 1 each row, correctly implementing sequential copy.

---

## 10. Conclusion

**Status**: SOUND

The data_copy.pil gadget is **correctly implemented** with:

- Permutations for all memory operations (read and write)
- Complete bounds checking via GT lookups
- Proper error handling (out-of-range addresses)
- Correct trace shape constraints preventing manipulation
- Special handling for top-level calldata reads
- Sound padding mechanism for partial copies

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

| Constraint | Purpose |
|------------|---------|
| TRACE_CONTINUITY | Trace shape |
| COMPUTATION_FINISH_AT_END | No premature stop |
| START_AFTER_LATCH | No extra rows |
| OFFSET_PLUS_SIZE_IS_GT_DATA_SIZE | Compute min |
| CHECK_SRC_ADDR_IN_RANGE | Read bounds |
| CHECK_DST_ADDR_IN_RANGE | Write bounds |
| ZERO_SIZED_WRITE | Handle copy_size=0 |
| END_IF_WRITE_IS_ZERO | End immediately if nothing to copy |
| END_WRITE_CONDITION | End when copy_size decrements to 1 |
| END_ON_ERR | End on error |
| INIT_READS_LEFT | Initialize read count |
| DECR_COPY_SIZE | Decrement writes remaining |
| INCR_WRITE_ADDR | Increment write address |
| DECR_READ_COUNT | Decrement reads remaining |
| INCR_READ_ADDR | Increment read address |
| PADDING_CONDITION | Detect padding state |
| PADDING_PROPAGATION | Stay in padding |
| PAD_VALUE | Zero on padding |
| MEM_WRITE | Permutation for memory write |
| MEM_READ | Permutation for memory read |
| COL_READ | Lookup for calldata read |
| TOP_LEVEL_COND | Detect top-level call |

## Appendix: Read Selector Logic

```
sel_mem_read = SEL_PERFORM_COPY * (1 - is_top_level * sel_cd_copy) * (1 - padding)
             = (no error) AND (copy_size > 0) AND (not top-level CD copy) AND (not padding)

cd_copy_col_read = SEL_PERFORM_COPY * (1 - padding) * is_top_level * sel_cd_copy
                 = (no error) AND (copy_size > 0) AND (top-level) AND (CD copy) AND (not padding)
```
