# Security Audit: alu.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `alu.pil` gadget implements the Arithmetic Logic Unit for the AVM2, handling:
- **Arithmetic**: ADD, SUB, MUL, DIV, FDIV
- **Comparison**: EQ, LT, LTE
- **Bitwise**: NOT
- **Bit Shifting**: SHL, SHR
- **Type Conversion**: TRUNCATE (for SET/CAST opcodes)

### Key Characteristics
- Single-row operations (no multi-row computations)
- Comprehensive error handling for tag mismatches and division by zero
- Integrates with range_check, gt, and ff_gt gadgets
- Supports all memory tags: U1, U8, U16, U32, U64, U128, FF

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/alu.pil` | PIL constraint definitions (668 lines) |
| `barretenberg/cpp/src/barretenberg/vm2/constraining/relations/alu.test.cpp` | Constraint tests |

---

## 3. Constraint Analysis

### 3.1 Operation Dispatch

**DISPATCH_OPERATION (line 116)**:
```
op_id = sel_op_add * constants.AVM_EXEC_OP_ID_ALU_ADD
      + sel_op_sub * constants.AVM_EXEC_OP_ID_ALU_SUB
      + ...
```
- Each `AVM_EXEC_OP_ID_*` is a power of 2
- Guarantees mutual exclusion of operation selectors

### 3.2 Tag Checking

**TAG_IS_FF (line 163)**:
```
sel * (TAG_FF_DIFF * (sel_is_ff * (1 - tag_ff_diff_inv) + tag_ff_diff_inv) + sel_is_ff - 1) = 0
```
- Proves `sel_is_ff = 1` iff `ia_tag = MEM_TAG_FF`

**TAG_IS_U128 (line 171)**:
```
sel * (TAG_U128_DIFF * (sel_is_u128 * (1 - tag_u128_diff_inv) + tag_u128_diff_inv) + sel_is_u128 - 1) = 0
```
- Proves `sel_is_u128 = 1` iff `ia_tag = MEM_TAG_U128`

### 3.3 Error Handling

**ERR_CHECK (line 198)**:
```
sel_err = sel_tag_err + sel_div_0_err - sel_tag_err * sel_div_0_err
```
- OR of tag error and div-by-zero error

**TAG_ERR_CHECK (line 202)**:
```
sel_tag_err = sel_ab_tag_mismatch + FF_TAG_ERR - sel_ab_tag_mismatch * FF_TAG_ERR
```
- OR of tag mismatch and FF tag error

**DIV_0_ERR (line 233)**:
```
DIV_OPS * (ib * (sel_div_0_err * (1 - b_inv) + b_inv) + sel_div_0_err - 1) = 0
```
- When DIV_OPS=1: `sel_div_0_err = 1` iff `ib = 0`

### 3.4 Arithmetic Operations

**ALU_ADD_SUB (line 336)**:
```
(sel_op_add + sel_op_sub) * (1 - sel_err) * (ia - ic + (sel_op_add - sel_op_sub) * (ib - cf * (max_value + 1))) = 0
```
- ADD: `ia + ib - cf * (max_value + 1) = ic`
- SUB: `ia - ib + cf * (max_value + 1) = ic`
- Carry flag `cf` handles overflow/underflow

**ALU_MUL_NON_U128 (line 353)**:
```
sel_op_mul * IS_NOT_U128 * (1 - sel_err) * (ia * ib - ic - (max_value + 1) * c_hi) = 0
```
- `ia * ib = ic + c_hi * (max_value + 1)`

**ALU_MUL_U128 (line 368)**:
```
SEL_MUL_U128 * (ia * b_lo + a_lo * b_hi * TWO_POW_64 - ic - (max_value + 1) * (cf * TWO_POW_64 + c_hi)) = 0
```
- Handles 128-bit multiplication with 64-bit limb decomposition

**ALU_DIV_U128 (line 418)**:
```
SEL_DIV_U128 * (ic * b_lo + a_lo * b_hi * TWO_POW_64 - (ia - helper1)) = 0
```
- Verifies `ic * b = a - remainder` where `helper1` stores remainder

### 3.5 Comparison Operations

**EQ_OP_MAIN (line 448)**:
```
sel_op_eq * (1 - sel_err) * (DIFF * (ic * (1 - ab_diff_inv) + ab_diff_inv) - 1 + ic) = 0
```
- Proves `ic = 1` iff `ia = ib`

**LT/LTE** via gt gadget lookups:
- FF_GT (line 482): Uses ff_gt gadget for field comparisons
- INT_GT (line 486): Uses gt gadget for integer comparisons

### 3.6 Shift Operations

**ALU_SHL (line 532)**:
```
sel_op_shl * (1 - sel_err) * (ic - sel_shift_ops_no_overflow * a_lo * helper1) = 0
```
- Result is `a_lo * 2^ib` where `a_lo` is the lower `(max_bits - ib)` bits of `ia`

**ALU_SHR (line 547)**:
```
sel_op_shr * (1 - sel_err) * (ic - sel_shift_ops_no_overflow * a_hi) = 0
```
- Result is `a_hi` where `a_hi` is the upper `(max_bits - ib)` bits of `ia`

### 3.7 Truncation

**TRUNC_TRIVIAL_CASE (line 636)**:
```
sel_trunc_trivial * (ia - ic) = 0
```

**TRUNC_LO_128_DECOMPOSITION (line 656)**:
```
sel_trunc_non_trivial * (ic + mid * (max_value + 1) - a_lo) = 0
```
- For values >= 2^128, uses ff_gt.sel_dec for canonical decomposition

---

## 4. Soundness Analysis

### 4.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Tag mismatch attack | AB_TAGS_CHECK | PROTECTED |
| FF tag on integer ops | FF_TAG_ERR | PROTECTED |
| Division by zero | DIV_0_ERR | PROTECTED |
| Overflow on MUL | c_hi range check | PROTECTED |
| Shift overflow | sel_shift_ops_no_overflow | PROTECTED |
| Wrong comparison | gt/ff_gt gadget lookups | PROTECTED |
| Truncation bypass | ff_gt.sel_dec lookup | PROTECTED |

### 4.2 Critical Constraints Verified

1. **Operation Mutual Exclusion**: Power-of-2 op_ids guarantee one operation per row
2. **Error Propagation**: sel_err correctly ORs all error conditions
3. **Tag Consistency**: C_TAG_CHECK enforces correct output tag
4. **Range Checks**: All limb decompositions are range-checked
5. **GT Verification**: Comparisons delegated to proven gadgets

### 4.3 Memory Write Preconditions

The ALU relies on memory.pil's `RANGE_CHECK_WRITE_TAGGED_VALUE` to enforce:
- Output `ic` is within `[0, 2^max_bits - 1]` for non-FF tags
- This provides implicit overflow protection for operations like ADD

---

## 5. Completeness Analysis

### 5.1 Trace Generation

From the test file analysis:
- All operations tested with trace generation
- Carry/overflow cases tested
- Error conditions properly handled
- All memory tags (U1-U128, FF) covered

### 5.2 Edge Cases

- **U128 MUL/DIV**: Uses 64-bit limb decomposition
- **Shift Overflow**: When `ib >= max_bits`, result is 0
- **FF Truncation**: Uses canonical decomposition via ff_gt

---

## 6. Integration Analysis

### 6.1 Dependencies

| Gadget | Usage |
|--------|-------|
| `range_check.pil` | Limb range checks, c_hi range check |
| `gt.pil` | Integer comparisons, DIV remainder check |
| `ff_gt.pil` | Field comparisons, truncation decomposition |
| `precomputed.pil` | Tag parameters, power of 2 lookup |

### 6.2 Execution Dispatch

Three dispatch lookups from `execution.pil`:
1. `DISPATCH_TO_ALU`: General ALU operations
2. `DISPATCH_TO_SET`: SET opcode truncation
3. `DISPATCH_TO_CAST`: CAST opcode truncation

---

## 7. Test Coverage Assessment

### 7.1 Positive Tests
- ADD/SUB with all tags (U1-U128, FF)
- MUL/DIV with and without overflow
- EQ/LT/LTE comparisons
- SHL/SHR with overflow detection
- TRUNCATE with trivial and non-trivial cases

### 7.2 Negative Tests
- Wrong op_id (DISPATCH_OPERATION)
- Wrong result (ALU_ADD_SUB, ALU_MUL_*, etc.)
- Tag mismatch (AB_TAGS_CHECK)
- Wrong output tag (C_TAG_CHECK)
- Error flag inconsistencies (ERR_CHECK, TAG_ERR_CHECK)

---

## 8. Findings

### No Critical Vulnerabilities Found

The ALU gadget is **SOUND** and **COMPLETE**.

### INFO-1: Carry Flag Trust

The ADD/SUB operations rely on the carry flag `cf` being correctly set. While a malicious prover could set `cf=0` when overflow occurs, the memory write range check would catch that `ic` exceeds `max_value`. This is documented in the comments.

### INFO-2: U128 Division Check

The constraint `ALU_DIV_U128_CHECK`:
```
SEL_DIV_U128 * a_hi * b_hi = 0
```
ensures that for 128-bit division, both dividend and divisor cannot have large high limbs simultaneously. This prevents field overflow in the multiplication check.

---

## 9. Conclusion

**Status**: SOUND

The alu.pil gadget correctly implements all arithmetic and logic operations with:
- Comprehensive error handling for invalid inputs
- Proper tag validation and output tag derivation
- Integration with range_check, gt, and ff_gt for complex operations
- Memory write range checks as an additional safety net

The constraint system is complete and no soundness vulnerabilities were identified.

---

## Appendix: Constraint Index

| Constraint | Line | Purpose |
|------------|------|---------|
| DISPATCH_OPERATION | 116 | Map op_id to selectors |
| TAG_IS_FF | 163 | Detect FF tag |
| TAG_IS_U128 | 171 | Detect U128 tag |
| ERR_CHECK | 198 | Consolidated error flag |
| TAG_ERR_CHECK | 202 | Tag error flag |
| AB_TAGS_CHECK | 217 | Tag mismatch check |
| DIV_0_ERR | 233 | Division by zero check |
| TAG_MAX_BITS_VALUE | 257 | Lookup tag parameters |
| C_TAG_CHECK | 269 | Output tag check |
| A_DECOMPOSITION | 296 | Decompose a into limbs |
| B_DECOMPOSITION | 298 | Decompose b into limbs |
| ALU_ADD_SUB | 336 | ADD/SUB operation |
| ALU_MUL_NON_U128 | 353 | MUL for non-U128 |
| ALU_MUL_U128 | 368 | MUL for U128 |
| ALU_DIV_U128_CHECK | 415 | DIV high limb check |
| ALU_DIV_U128 | 418 | DIV for U128 |
| ALU_FDIV_DIV_NON_U128 | 435 | DIV/FDIV for non-U128 |
| EQ_OP_MAIN | 448 | EQ operation |
| FF_GT | 482 | FF comparison lookup |
| INT_GT | 486 | Integer comparison lookup |
| NOT_OP_MAIN | 496 | NOT operation |
| ALU_SHL | 532 | SHL operation |
| ALU_SHR | 547 | SHR operation |
| TRUNC_TRIVIAL_CASE | 636 | Trivial truncation |
| TRUNC_LO_128_DECOMPOSITION | 656 | Truncation decomposition |
