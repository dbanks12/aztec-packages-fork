# Security Audit: data_copy.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `data_copy.pil` gadget handles CALLDATACOPY and RETURNDATACOPY operations, copying data between memory spaces or from the calldata column.

### Key Characteristics
- Multi-row operation: `copy_size` rows (or 1 row for error/empty)
- Handles cross-context memory reads and writes
- Supports top-level calldata column reads
- Error handling for out-of-range memory access

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/data_copy.pil` | PIL constraint definitions (405 lines) |

---

## 3. Constraint Analysis

### 3.1 Trace Shape

**TRACE_CONTINUITY (line 151)**:
```
(1 - precomputed.first_row) * (1 - sel) * sel' = 0
```
- Trace is contiguous

**COMPUTATION_FINISH_AT_END (line 165)**:
```
sel * (1 - sel') * (1 - sel_end) = 0
```
- Cannot stop before `sel_end = 1`

**START_AFTER_LATCH (line 176)**:
```
sel' * (sel_start' - LATCH_CONDITION) = 0
```
- New computation starts after end

### 3.2 Error Handling

**CHECK_SRC_ADDR_IN_RANGE / CHECK_DST_ADDR_IN_RANGE (lines 254-264)**:
```
sel_start { read_addr_upper_bound, mem_size, src_out_of_range_err } in gt.sel_others { ... }
sel_start { write_addr_upper_bound, mem_size, dst_out_of_range_err } in gt.sel_others { ... }
```

**Error consolidation (line 269)**:
```
err = 1 - (1 - dst_out_of_range_err) * (1 - src_out_of_range_err)
```

### 3.3 Data Index Upper Bound

**Min computation (lines 222-229)**:
```
offset_plus_size_is_gt: lookup into gt to check if offset + copy_size > src_data_size
data_index_upper_bound = (src_data_size - offset_plus_size) * offset_plus_size_is_gt + offset_plus_size
```
- Ensures we don't read past designated data bounds

### 3.4 Memory Operations

**MEM_WRITE (lines 338-341)**:
```
sel_mem_write { clk, dst_context_id, dst_addr, value, 0/*FF*/, 1/*write*/ }
is memory.sel_data_copy_write { ... }
```

**MEM_READ (lines 386-389)**:
```
sel_mem_read { clk, src_context_id, read_addr, value, tag, 0/*read*/ }
is memory.sel_data_copy_read { ... }
```

### 3.5 Padding and Value Constraints

**PADDING_CONDITION (line 358)**:
```
SEL_PERFORM_COPY * (reads_left * (padding * (1 - reads_left_inv) + reads_left_inv) - 1 + padding) = 0
```
- `padding = 1` iff `reads_left = 0`

**PAD_VALUE (line 382)**:
```
padding * value = 0
```
- Padding rows have value = 0

### 3.6 Top-Level Calldata

**COL_READ (lines 401-404)**:
```
cd_copy_col_read { read_addr_plus_one, dst_context_id, value }
in calldata.sel { calldata.index, calldata.context_id, calldata.value }
```
- Top-level calldatacopy reads from calldata column

---

## 4. Soundness Analysis

### 4.1 Attack Surface

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Read past data bounds | data_index_upper_bound computation | PROTECTED |
| Write out of memory | dst_out_of_range_err check | PROTECTED |
| Fake memory ops | Permutation (not lookup) | PROTECTED |
| Wrong padding | PADDING_CONDITION + PAD_VALUE | PROTECTED |
| Skip rows | COMPUTATION_FINISH_AT_END | PROTECTED |

### 4.2 Permutation vs Lookup

Memory operations use **permutation** (`is` keyword) rather than lookup to prevent malicious insertions into the memory trace. This is critical for security.

---

## 5. Findings

### No Critical Vulnerabilities Found

The data_copy gadget is **SOUND**.

### INFO-1: Two Dispatch Selectors

The gadget has separate selectors for calldatacopy and returndatacopy (`sel_cd_copy_start`, `sel_rd_copy_start`) to interact with different execution trace columns.

---

## 6. Conclusion

**Status**: SOUND

The data_copy.pil gadget correctly implements data copy operations with:
- Proper bounds checking for source and destination
- Correct padding for reads beyond data bounds
- Secure permutation-based memory integration
- Top-level calldata column support
