# Deep Security Audit: alu.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL file: `pil/vm2/alu.pil` (668 lines)
- [x] Located dependencies: ff_gt.pil, gt.pil, range_check.pil, precomputed.pil
- [x] Located callers: execution.pil (#[DISPATCH_TO_ALU], #[DISPATCH_TO_SET], #[DISPATCH_TO_CAST])
- [x] Located tests: alu.test.cpp
- [x] Identified 12 operations

### Phase 2: Understanding
- [x] Documented gadget purpose (arithmetic operations)
- [x] Listed all witnesses
- [x] Listed all constraints
- [x] Listed all lookups
- [x] Understood error handling

### Phase 3: Soundness
- [x] Verified operation dispatch
- [x] Analyzed overflow handling
- [x] Checked limb decomposition
- [x] Verified error propagation

### Phase 4: Completeness
- [x] Reviewed range check usage
- [x] Checked edge cases
- [x] Verified tag handling

### Phase 5: Integration
- [x] Verified execution dispatch
- [x] Checked GT gadget interaction
- [x] Verified memory preconditions

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/alu.pil` | 668 | Arithmetic operations |
| `pil/vm2/ff_gt.pil` | ~100 | Field comparison |
| `pil/vm2/gt.pil` | ~200 | Integer comparison |
| Tests | 500+ | Operation tests |

---

## 2. Gadget Architecture

### 2.1 Purpose

The ALU gadget performs arithmetic and logical operations:

| Operation | Opcode | Description |
|-----------|--------|-------------|
| ADD | sel_op_add | a + b mod 2^k |
| SUB | sel_op_sub | a - b mod 2^k |
| MUL | sel_op_mul | a * b mod 2^k |
| DIV | sel_op_div | a / b (integer) |
| FDIV | sel_op_fdiv | a / b (field) |
| EQ | sel_op_eq | a == b ? 1 : 0 |
| LT | sel_op_lt | a < b ? 1 : 0 |
| LTE | sel_op_lte | a <= b ? 1 : 0 |
| NOT | sel_op_not | ~a |
| SHL | sel_op_shl | a << b |
| SHR | sel_op_shr | a >> b |
| TRUNCATE | sel_op_truncate | Truncate to target tag |

### 2.2 Memory Preconditions

From PIL comments:
```
PRECONDITIONS: a, b, c are in range [0, 2^max_bits - 1] for non-FF values.
Enforced through range check on every MemoryValue during memory write.
```

This means ALU does NOT need to range check inputs - memory.pil guarantees them.

### 2.3 Usage Patterns

```pil
// 1. General ALU dispatch
#[DISPATCH_TO_ALU]
sel_exec_dispatch_alu { register[0], mem_tag_reg[0], ... } in alu.sel { alu.ia, alu.ia_tag, ... };

// 2. SET dispatch (truncate immediate to tag)
#[DISPATCH_TO_SET]
sel_exec_dispatch_set { rop[2], rop[1], register[0], mem_tag_reg[0], sel_exec_dispatch_set, sel_opcode_error }
in alu.sel_op_truncate { alu.ia, alu.ia_tag, alu.ic, alu.ia_tag, alu.sel, precomputed.zero };

// 3. CAST dispatch (truncate value to new tag)
#[DISPATCH_TO_CAST]
sel_exec_dispatch_cast { ... } in alu.sel_op_truncate { ... };
```

---

## 3. Operation Dispatch

### 3.1 Mutual Exclusivity

```pil
// alu.pil:115-127
#[DISPATCH_OPERATION]
op_id = sel_op_add * constants.AVM_EXEC_OP_ID_ALU_ADD
      + sel_op_sub * constants.AVM_EXEC_OP_ID_ALU_SUB
      // ... each constant is a power of 2
      + sel_op_truncate * constants.AVM_EXEC_OP_ID_ALU_TRUNCATE;
```

**Security**: Since each `AVM_EXEC_OP_ID_*` is a power of 2, and `op_id` is constrained by the lookup from execution, exactly one `sel_op_*` can be 1.

### 3.2 Tag Detection

```pil
// alu.pil:159-171
// sel_is_ff == 1 iff ia_tag == MEM_TAG_FF (zero-check pattern)
#[TAG_IS_FF]
sel * (TAG_FF_DIFF * (sel_is_ff * (1 - tag_ff_diff_inv) + tag_ff_diff_inv) + sel_is_ff - 1) = 0;

// Similar for sel_is_u128
#[TAG_IS_U128]
sel * (TAG_U128_DIFF * (sel_is_u128 * (1 - tag_u128_diff_inv) + tag_u128_diff_inv) + sel_is_u128 - 1) = 0;
```

---

## 4. Error Handling

### 4.1 Error Hierarchy

```
sel_err = sel_tag_err OR sel_div_0_err
    │
    ├── sel_tag_err = sel_ab_tag_mismatch OR FF_TAG_ERR
    │       │
    │       ├── sel_ab_tag_mismatch: ia_tag != ib_tag (except TRUNCATE, NOT)
    │       │
    │       └── FF_TAG_ERR: FF tag with DIV/NOT/SHL/SHR, or non-FF with FDIV
    │
    └── sel_div_0_err: ib == 0 for DIV/FDIV
```

### 4.2 Error Constraints

```pil
// alu.pil:197-202
#[ERR_CHECK]
sel_err = sel_tag_err + sel_div_0_err - sel_tag_err * sel_div_0_err; // OR

#[TAG_ERR_CHECK]
sel_tag_err = sel_ab_tag_mismatch + FF_TAG_ERR - sel_ab_tag_mismatch * FF_TAG_ERR; // OR
```

### 4.3 FF Tag Error

```pil
// alu.pil:207
pol FF_TAG_ERR = (sel_op_div + sel_op_not + SHIFT_OPS) * sel_is_ff + sel_op_fdiv * IS_NOT_FF;
```

- DIV, NOT, SHL, SHR: Error if input is FF (requires bounded integer)
- FDIV: Error if input is NOT FF (requires field element)

### 4.4 Division by Zero

```pil
// alu.pil:230-237
#[DIV_0_ERR]
DIV_OPS * (ib * (sel_div_0_err * (1 - b_inv) + b_inv) + sel_div_0_err - 1) = 0;

#[ONLY_RELEVANT_CHECK_DIV_0_ERR_ERROR]
(1 - DIV_OPS) * sel_div_0_err = 0;
```

Zero-check pattern: `sel_div_0_err = 1` iff `ib = 0` (when DIV/FDIV).

---

## 5. Arithmetic Operations

### 5.1 ADD & SUB

```pil
// alu.pil:335-336
#[ALU_ADD_SUB]
(sel_op_add + sel_op_sub) * (1 - sel_err)
  * (ia - ic + (sel_op_add - sel_op_sub) * (ib - cf * (max_value + 1))) = 0;
```

**Analysis**:
- ADD: `ia + ib - cf * (max_value + 1) = ic` where `cf` is carry flag
- SUB: `ia - ib + cf * (max_value + 1) = ic` where `cf` is borrow flag

Memory range check ensures `ic` is in valid range, so overflow is correctly handled.

### 5.2 MUL (non-u128)

```pil
// alu.pil:352-353
#[ALU_MUL_NON_U128]
sel_op_mul * IS_NOT_U128 * (1 - sel_err) * (ia * ib - ic - (max_value + 1) * c_hi) = 0;
```

**Analysis**: `ia * ib = ic + c_hi * (max_value + 1)` where:
- `c_hi` is the high part of the product
- `c_hi < 2^64` (range checked)
- `ic < max_value + 1` (memory range check)

For FF: `max_value + 1 = 0` in the field, so relation becomes `ia * ib = ic`.

### 5.3 MUL (u128)

```pil
// alu.pil:367-372
#[ALU_MUL_U128]
SEL_MUL_U128 * (
    ia * b_lo + a_lo * b_hi * TWO_POW_64  // a * b without hi bits
    - ic                                   // c_lo
    - (max_value + 1) * (cf * TWO_POW_64 + c_hi)
) = 0;
```

**Analysis**: Uses 64-bit limb decomposition:
- `a = a_lo + a_hi * 2^64`
- `b = b_lo + b_hi * 2^64`
- Product computed modulo 2^128

### 5.4 DIV (u128)

```pil
// alu.pil:414-418
#[ALU_DIV_U128_CHECK]
SEL_DIV_U128 * a_hi * b_hi = 0;

#[ALU_DIV_U128]
SEL_DIV_U128 * (ic * b_lo + a_lo * b_hi * TWO_POW_64 - (ia - helper1)) = 0;
```

**Analysis**:
- `c * b = a - remainder` where `remainder = helper1`
- `a_hi * b_hi = 0` ensures no overflow
- Remainder check via `#[INT_GT]`: `b > remainder`

### 5.5 FDIV

```pil
// alu.pil:434-435
#[ALU_FDIV_DIV_NON_U128]
DIV_OPS_NON_U128 * (ib * ic - ia + sel_op_div * helper1) = 0;
```

For FDIV: `b * c = a` (no remainder in field division).

---

## 6. Comparison Operations

### 6.1 EQ

```pil
// alu.pil:447-448
#[EQ_OP_MAIN]
sel_op_eq * (1 - sel_err) * (DIFF * (ic * (1 - ab_diff_inv) + ab_diff_inv) - 1 + ic) = 0;
```

Zero-check pattern: `ic = 1` iff `ia - ib = 0`.

### 6.2 LT & LTE

```pil
// alu.pil:472-487
#[GT_INPUT_A]
gt_input_a = (sel_op_lt + sel_div_no_err) * ib + sel_op_lte * ia;

#[GT_INPUT_B]
gt_input_b = sel_op_lt * ia + sel_op_lte * ib + sel_div_no_err * helper1;

#[GT_ASSIGN_RESULT_C]
(1 - sel_err) * (sel_div_no_err + sel_op_lt * ic + sel_op_lte * (1 - ic) - gt_result_c) = 0;

#[FF_GT]
sel_ff_gt { gt_input_a, gt_input_b, gt_result_c } in ff_gt.sel_gt { ... };

#[INT_GT]
sel_int_gt { gt_input_a, gt_input_b, gt_result_c } in gt.sel_alu { ... };
```

**Analysis**:
- LT: Use GT with swapped inputs: `b > a ? ic`
- LTE: Use GT with negated result: `a > b ? !ic`
- DIV: Use GT for remainder check: `b > remainder ? 1`

---

## 7. Bitwise Operations

### 7.1 NOT

```pil
// alu.pil:495-496
#[NOT_OP_MAIN]
sel_op_not * (1 - sel_err) * (ia + ib - max_value) = 0;
```

**Analysis**: `a + ~a = 2^k - 1 = max_value`.

### 7.2 SHL & SHR

**Decomposition Strategy**:

For SHL with `a` shifted left by `s` bits (max `t` bits):
```
 <-- s bits -->   | <-- (t-s) bits -->
------------------|-------------------
|      a_hi       |      a_lo        | --> output = a_lo * 2^s
--------------------------------------
```

For SHR with `a` shifted right by `s` bits:
```
 <--(t-s) bits --> |   <-- s bits -->
-------------------|-------------------
|      a_hi        |       a_lo       | --> output = a_hi
---------------------------------------
```

**Overflow Handling**:
```pil
// alu.pil:556
pol SHIFT_OVERFLOW = SHIFT_OPS * (1 - sel_shift_ops_no_overflow);
```

When `s >= max_bits`:
- `sel_shift_ops_no_overflow = 0`
- `ic = 0` (trivially)

---

## 8. TRUNCATE Operation

### 8.1 Three Cases

```pil
// alu.pil:631-632
#[SEL_TRUNC_NON_TRIVIAL]
sel_trunc_non_trivial = sel_trunc_gte_128 + sel_trunc_lt_128;

#[SEL_TRUNCATE]
sel_op_truncate = sel_trunc_non_trivial + sel_trunc_trivial;
```

1. **Trivial**: `ia <= max_value` → `ic = ia`
2. **Large (>= 2^128)**: Use ff_gt.sel_dec for canonical decomposition
3. **Small (< 2^128)**: Direct decomposition

### 8.2 Decomposition

```pil
// alu.pil:655-656
#[TRUNC_LO_128_DECOMPOSITION]
sel_trunc_non_trivial * (ic + mid * (max_value + 1) - a_lo) = 0;
```

**Analysis**: `a_lo = ic + mid * (max_value + 1)` where:
- `ic < max_value + 1` (memory range check)
- `mid < 2^(128 - max_bits)` (range check)

---

## 9. Range Check Usage

### 9.1 Limb Decomposition

```pil
// alu.pil:313-323
#[RANGE_CHECK_DECOMPOSITION_A_LO]
sel_decompose_a { a_lo, a_lo_bits } in range_check.sel_alu { ... };

#[RANGE_CHECK_DECOMPOSITION_A_HI]
sel_decompose_a { a_hi, a_hi_bits } in range_check.sel_alu { ... };
```

### 9.2 MUL c_hi

```pil
// alu.pil:377-378
#[RANGE_CHECK_MUL_C_HI]
sel_mul_no_err_non_ff { c_hi, constant_64 } in range_check.sel_alu { ... };
```

### 9.3 TRUNCATE mid

```pil
// alu.pil:666-667
#[RANGE_CHECK_TRUNC_MID]
sel_trunc_non_trivial { mid, mid_bits } in range_check.sel_alu { ... };
```

---

## 10. Soundness Verification

### 10.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Multiple operation selectors | Power-of-2 decomposition | PROTECTED |
| Wrong tag detection | Zero-check patterns | PROTECTED |
| Skip error flag | Error propagation to execution | PROTECTED |
| Overflow manipulation | Memory range check on output | PROTECTED |
| Wrong limb decomposition | Range checks on limbs | PROTECTED |
| Division by zero | sel_div_0_err with zero-check | PROTECTED |
| Comparison manipulation | GT gadget lookups | PROTECTED |
| Shift overflow | sel_shift_ops_no_overflow constraints | PROTECTED |
| Truncate wrong value | ff_gt canonical decomposition | PROTECTED |

### 10.2 Critical Security Property: Memory Precondition

The ALU relies on memory.pil's `#[RANGE_CHECK_WRITE_TAGGED_VALUE]` to bound inputs. This is correct because:
1. All ALU inputs come from memory (registers)
2. Memory enforces range on write
3. ALU only needs to range check intermediate values (c_hi, limbs, mid)

### 10.3 Output Tag Correctness

```pil
// alu.pil:262-269
pol EXPECTED_C_TAG = (sel_op_add + ...) * ia_tag
                   + (sel_op_eq + ...) * constants.MEM_TAG_U1
                   + sel_op_fdiv * constants.MEM_TAG_FF;

#[C_TAG_CHECK]
(1 - sel_err) * (EXPECTED_C_TAG - ic_tag) = 0;
```

Output tag is correctly computed based on operation type.

---

## 11. Findings

### No Critical Vulnerabilities Found

The alu.pil gadget is **SOUND**.

### INFO-1: Comprehensive Operation Coverage

12 operations with proper error handling, tag checking, and range constraints.

### INFO-2: Power-of-2 ID Scheme

Using power-of-2 constants for operation IDs guarantees mutual exclusivity through binary decomposition.

### INFO-3: Memory Precondition Dependency

The ALU's correctness depends on memory.pil's range check. This is documented and appropriate.

### INFO-4: Reused Columns

The ALU reuses `a_lo`, `a_hi`, `b_lo`, `b_hi` columns across MUL, DIV, SHL, SHR, and TRUNCATE. The `#[DISPATCH_OPERATION]` ensures only one operation is active, making this safe.

### INFO-5: GT Gadget Reuse for DIV

The DIV operation reuses the GT gadget infrastructure (gt_input_a/b, gt_result_c) to prove `remainder < divisor`. This is an elegant design.

---

## 12. Conclusion

**Status**: SOUND

The alu.pil gadget is **correctly implemented** with:

- Proper operation dispatch via power-of-2 decomposition
- Complete error handling (tag mismatch, FF errors, div-by-zero)
- Correct arithmetic constraints for all operations
- Sound limb decomposition with range checks
- Appropriate GT gadget integration for comparisons
- Memory precondition correctly leveraged

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Operation Summary

| Operation | Error Conditions | Output Tag | Range Checks |
|-----------|------------------|------------|--------------|
| ADD | Tag mismatch | ia_tag | (memory) |
| SUB | Tag mismatch | ia_tag | (memory) |
| MUL | Tag mismatch | ia_tag | c_hi, limbs (u128) |
| DIV | Tag mismatch, FF, div-0 | ia_tag | limbs (u128), remainder |
| FDIV | Tag mismatch, non-FF, div-0 | FF | (memory) |
| EQ | Tag mismatch | U1 | (memory) |
| LT | Tag mismatch | U1 | (via GT) |
| LTE | Tag mismatch | U1 | (via GT) |
| NOT | FF | ia_tag | (memory) |
| SHL | Tag mismatch, FF | ia_tag | limbs |
| SHR | Tag mismatch, FF | ia_tag | limbs |
| TRUNCATE | (none) | ia_tag | mid |

## Appendix: Limb Usage

| Operation | a_lo | a_hi | b_lo | b_hi |
|-----------|------|------|------|------|
| MUL (u128) | ia bits 0-63 | ia bits 64-127 | ib bits 0-63 | ib bits 64-127 |
| DIV (u128) | ic bits 0-63 | ic bits 64-127 | ib bits 0-63 | ib bits 64-127 |
| SHL | ia bits 0-(t-s-1) | ia bits (t-s)-(t-1) | - | - |
| SHR | ia bits 0-(s-1) | ia bits s-(t-1) | - | - |
| TRUNCATE | ia bits 0-127 | - | - | - |
