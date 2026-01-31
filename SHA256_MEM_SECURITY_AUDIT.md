# Security Audit: sha256_mem.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `sha256_mem.pil` (virtual to sha256.pil namespace) handles memory operations for the SHA256Compression opcode. It processes the SHA256 compression function across 65 rows (64 rounds + 1 output row), managing memory reads for state and inputs, and writes for outputs.

### Key Characteristics
- Multi-row operation: 65 rows per SHA256 compression
- Reads 8 U32 state values horizontally
- Reads 16 U32 input values vertically (one per row)
- Writes 8 U32 output values horizontally
- Comprehensive error handling for out-of-bounds and invalid tags

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/sha256_mem.pil` | PIL constraint definitions (460 lines) |

---

## 3. Constraint Analysis

### 3.1 Lifecycle Constraints

**TRACE_CONTINUITY (line 99)**:
```
(1 - precomputed.first_row) * (1 - sel) * sel' = 0
```

**START_AFTER_LAST (line 128)**:
```
sel' * (start' - LATCH_CONDITION) = 0
```
Where `LATCH_CONDITION = latch + precomputed.first_row`.

**LATCH_HAS_SEL_ON (line 123)**:
```
latch * (1 - sel) = 0
```

### 3.2 Propagation Constraints

**CONTINUITY_EXEC_CLK (line 136)**:
```
(1 - LATCH_CONDITION) * (execution_clk' - execution_clk) = 0
```

**CONTINUITY_SPACE_ID (line 138)**:
```
(1 - LATCH_CONDITION) * (space_id' - space_id) = 0
```

**CONTINUITY_INPUT_ADDR (line 146)**:
```
(1 - LATCH_CONDITION) * (input_addr' - (input_addr + sel_is_input_round)) = 0
```
- Prevents malicious address jumps during input loading

### 3.3 Out-of-Bounds Error Handling

**CHECK_STATE_ADDR_IN_RANGE (line 166)**:
```
start { max_state_addr, max_mem_addr, sel_state_out_of_range_err }
in gt.sel_others { gt.input_a, gt.input_b, gt.res };
```

**CHECK_INPUT_ADDR_IN_RANGE (line 173)**:
```
start { max_input_addr, max_mem_addr, sel_input_out_of_range_err }
in gt.sel_others { gt.input_a, gt.input_b, gt.res };
```

**CHECK_OUTPUT_ADDR_IN_RANGE (line 180)**:
```
start { max_output_addr, max_mem_addr, sel_output_out_of_range_err }
in gt.sel_others { gt.input_a, gt.input_b, gt.res };
```

### 3.4 Tag Validation

**BATCH_ZERO_CHECK_READ (line 365)**:
```
(STATE_READ_CONDITION * BATCHED_TAG_CHECK) * ((1 - sel_invalid_state_tag_err) * (1 - batch_tag_inv) + batch_tag_inv) - sel_invalid_state_tag_err = 0
```
- Uses batched zero-check with powers of 2 for efficiency

**INPUT_TAG_DIFF_CHECK (line 438)**:
```
INPUT_TAG_DIFF * ((1 - sel_invalid_input_row_tag_err) * (1 - input_tag_diff_inv) + input_tag_diff_inv) - sel_invalid_input_row_tag_err = 0
```

### 3.5 Memory Operations

**MEM_OP_0 through MEM_OP_7 (lines 247-341)**:
- 8 permutations for parallel state read/output write
- Uses `sel_mem_state_or_output` selector
- `rw` flag distinguishes reads from writes

**MEM_INPUT_READ (line 411)**:
```
sel_read_input_from_memory { ... } is memory.sel_sha256_read { ... };
```

### 3.6 Error Consolidation

**Error flag (line 458)**:
```
err = 1 - (1 - mem_out_of_range_err) * (1 - sel_invalid_state_tag_err) * (1 - sel_invalid_input_tag_err)
```

---

## 4. Soundness Analysis

### 4.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| State address overflow | CHECK_STATE_ADDR_IN_RANGE + gt lookup | PROTECTED |
| Input address overflow | CHECK_INPUT_ADDR_IN_RANGE + gt lookup | PROTECTED |
| Output address overflow | CHECK_OUTPUT_ADDR_IN_RANGE + gt lookup | PROTECTED |
| Invalid state tag | BATCH_ZERO_CHECK_READ | PROTECTED |
| Invalid input tag | INPUT_TAG_DIFF_CHECK | PROTECTED |
| Skip input rows | SEL_IS_INPUT_ROUND + counter decrement | PROTECTED |
| Address manipulation | CONTINUITY_INPUT_ADDR | PROTECTED |
| Ghost row writes | OUTPUT_WRITE_CONDITION includes (1-err) | PROTECTED |

### 4.2 Critical Constraints Verified

1. **Selector Lifecycle**: start/latch properly bound trace
2. **Input Counter**: Decrements correctly through 16 inputs
3. **Address Increments**: Input address increments by 1 each round
4. **Tag Batching**: Powers of 2 ensure tag differences don't collide
5. **Error Propagation**: TAG_ERROR_PROPAGATION lifts errors to start row

### 4.3 Batched Tag Check Security

The batched tag check uses:
```
BATCHED_TAG_CHECK = 2^0 * DIFF_0 + 2^3 * DIFF_1 + ... + 2^21 * DIFF_7
```

Since tag values are small (0-6), tag differences fit in 3 bits. Using powers 0, 3, 6, ..., 21 ensures no overlap between tag difference contributions.

---

## 5. Findings

### No Critical Vulnerabilities Found

The sha256_mem gadget is **SOUND**.

### INFO-1: Memory Column Reuse

The gadget reuses `memory_address`, `memory_register`, and `memory_tag` columns between state reads (start) and output writes (latch). This is safe because:
- `STATE_READ_CONDITION` and `OUTPUT_WRITE_CONDITION` are mutually exclusive
- Error on start forces `latch = 1` but `err = 1`, so `OUTPUT_WRITE_CONDITION = 0`

### INFO-2: Error Propagation Design

Input tag errors are detected per-row (`sel_invalid_input_row_tag_err`) and propagated upward to the start row (`sel_invalid_input_tag_err`). This design ensures the consolidated `err` flag is available for the permutation to execution.

---

## 6. Conclusion

**Status**: SOUND

The sha256_mem gadget correctly implements memory operations for SHA256 compression with:
- Proper out-of-bounds checking via gt lookups
- Efficient batched tag validation
- Correct error propagation
- Safe memory column reuse between reads and writes

The constraint system is complete and no soundness vulnerabilities were identified.
