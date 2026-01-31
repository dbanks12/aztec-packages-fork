# Deep Security Audit: bitwise.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL file: `pil/vm2/bitwise.pil` (278 lines)
- [x] Located dependencies: precomputed.pil
- [x] Located callers: execution.pil, keccakf1600.pil, sha256.pil
- [x] Identified multi-row byte decomposition structure

### Phase 2: Understanding
- [x] Documented gadget purpose (AND/OR/XOR operations)
- [x] Listed all witnesses
- [x] Listed all constraints
- [x] Understood byte lookup mechanism

### Phase 3: Soundness
- [x] Verified counter constraints
- [x] Analyzed accumulator relations
- [x] Checked tag error handling
- [x] Verified PR #19875 security fix

### Phase 4: Completeness
- [x] Reviewed byte decomposition
- [x] Checked edge cases
- [x] Verified error propagation

### Phase 5: Integration
- [x] Verified execution dispatch
- [x] Checked keccak/sha256 invocation
- [x] Verified start selector security

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/bitwise.pil` | 278 | Bitwise AND/OR/XOR operations |
| Tests | ~200 | Constraint tests |

---

## 2. Gadget Architecture

### 2.1 Purpose

The bitwise gadget performs AND, OR, XOR operations on non-FF integer types by:
1. Decomposing inputs into 8-bit chunks
2. Looking up byte-level operation results in precomputed table
3. Accumulating byte results back to full value

### 2.2 Multi-Row Structure

For a U32 operation `a AND b = c`:

```
ctr | sel | start | last | acc_ia     | acc_ic     | ia_byte | ic_byte
 4  |  1  |   1   |  0   | 0x52488425 | 0x42000024 |   0x25  |   0x24
 3  |  1  |   0   |  0   | 0x524884   | 0x420000   |   0x84  |   0x00
 2  |  1  |   0   |  0   | 0x5248     | 0x4200     |   0x48  |   0x00
 1  |  1  |   0   |  1   | 0x52       | 0x42       |   0x52  |   0x42
```

- `ctr`: Counter from `tag_byte_length` down to 1
- `start`: First row of operation (captures inputs/outputs)
- `last`: Last row of operation (`ctr = 1`)

### 2.3 Invocation Patterns

**1. From execution (with error handling):**
```pil
sel_exec_dispatch_bitwise { op_id, err, acc_ia, tag_a, acc_ib, tag_b, acc_ic, tag_c }
in bitwise.start { ... };
```

**2. From keccak/sha256 (without error handling):**
```pil
sel_XXX { a, b, c, xor_sel, tag_a }
in bitwise.start_XXX { bitwise.acc_ia, bitwise.acc_ib, bitwise.acc_ic, bitwise.op_id, bitwise.tag_a };
```

---

## 3. Counter and Selector Constraints

### 3.1 sel ↔ ctr Relationship

```pil
// bitwise.pil:193-194
pol commit ctr_inv;
#[BITW_SEL_CTR_NON_ZERO]
ctr * ((1 - sel) * (1 - ctr_inv) + ctr_inv) - sel = 0;
```

**Analysis**: Zero-check pattern ensuring `sel = 1` iff `ctr != 0`.

### 3.2 last ↔ ctr Relationship

```pil
// bitwise.pil:199-200
pol commit ctr_min_one_inv;
#[BITW_LAST_FOR_CTR_ONE]
sel * ((ctr - 1) * (last * (1 - ctr_min_one_inv) + ctr_min_one_inv) + last - 1) = 0;
```

**Analysis**: Zero-check pattern ensuring `last = 1` iff `ctr = 1` (when `sel = 1`).

### 3.3 Counter Decrement

```pil
// bitwise.pil:184-186
#[BITW_CTR_DECREMENT]
sel * (ctr' - ctr + 1) * (1 - last) = 0;
```

**Analysis**: `ctr' = ctr - 1` unless `last = 1` or `sel = 0`.

---

## 4. Accumulator Constraints

### 4.1 Initialization (last row)

```pil
// bitwise.pil:203-208
#[BITW_INIT_A]
last * (acc_ia - ia_byte) = 0;
#[BITW_INIT_B]
last * (acc_ib - ib_byte) = 0;
#[BITW_INIT_C]
last * (acc_ic - ic_byte) = 0;
```

**Analysis**: On the last row, accumulator equals the byte value (MSB).

### 4.2 Accumulation (non-last rows)

```pil
// bitwise.pil:210-215
#[BITW_ACC_REL_A]
(acc_ia - ia_byte - 256 * acc_ia') * (1 - last) = 0;
// Similar for B and C
```

**Analysis**: `acc_ia = ia_byte + 256 * acc_ia'`

This reconstructs the full value: `acc = byte₀ + 256*byte₁ + 256²*byte₂ + ...`

---

## 5. Tag Error Handling

### 5.1 FF Tag Error

```pil
// bitwise.pil:151-153
pol TAG_A_DIFF = tag_a - constants.MEM_TAG_FF;
#[INPUT_TAG_CANNOT_BE_FF]
start * (TAG_A_DIFF * (sel_tag_ff_err * (1 - tag_a_inv) + tag_a_inv) - 1 + sel_tag_ff_err) = 0;
```

**Analysis**: `sel_tag_ff_err = 1` iff `tag_a = MEM_TAG_FF` (which is 0).

### 5.2 Tag Mismatch Error

```pil
// bitwise.pil:156-160
pol TAG_AB_DIFF = tag_a - tag_b;
#[INPUT_TAGS_SHOULD_MATCH]
start * (TAG_AB_DIFF * ((1 - sel_tag_mismatch_err) * (1 - tag_ab_diff_inv) + tag_ab_diff_inv) - sel_tag_mismatch_err) = 0;
```

**Analysis**: `sel_tag_mismatch_err = 1` iff `tag_a != tag_b`.

### 5.3 Consolidated Error

```pil
// bitwise.pil:124
err = 1 - (1 - sel_tag_mismatch_err) * (1 - sel_tag_ff_err); // OR
```

### 5.4 Error Forces Last

```pil
// bitwise.pil:128-129
#[LAST_ON_ERROR]
err * (last - 1) = 0;
```

**Analysis**: If `err = 1`, then `last = 1`, preventing further computation.

---

## 6. Security Fix: PR #19875

### 6.1 Vulnerability Description

From comments:
> Crucial constraint to prevent the vulnerability described in PR #19875 consisting
> of maliciously setting start=1 on inactive rows (sel=0) by toggling an error
> and forging in any bitwise operation result.

### 6.2 Fix Constraint

```pil
// bitwise.pil:105-108
#[BITW_START_ONLY_WHEN_SEL]
(start_keccak + start_sha256) * (1 - sel) = 0;
// Note: the more general `start * (1 - sel) = 0` would be too aggressive since error rows
// legitimately need start=1 with sel=0 for the execution dispatch (#[DISPATCH_TO_BITWISE]).
```

**Analysis**:
- `start_keccak` and `start_sha256` are used for error-free invocations from keccak/sha256
- These MUST have `sel = 1` (active computation row)
- The execution dispatch allows `start = 1` with `sel = 0` when `err = 1` (error row has no computation)

This is a nuanced fix that allows error handling while preventing ghost rows from forging results.

---

## 7. Byte Lookup

### 7.1 Counter Initialization

```pil
// bitwise.pil:219-225
pol commit sel_get_ctr;
sel_get_ctr = start * (1 - err);

#[INTEGRAL_TAG_LENGTH]
sel_get_ctr { tag_a, ctr } in precomputed.sel_tag_parameters { precomputed.clk, precomputed.tag_byte_length };
```

**Analysis**: Counter is looked up only on `start` row without error.

### 7.2 Byte Operation Lookup

```pil
// bitwise.pil:227-230
#[BYTE_OPERATIONS]
sel { op_id, ia_byte, ib_byte, ic_byte }
in precomputed.sel_bitwise { precomputed.bitwise_op_id, precomputed.bitwise_input_a, precomputed.bitwise_input_b, precomputed.bitwise_output };
```

**Analysis**: Every active row (`sel = 1`) looks up byte-level operation in precomputed table.

---

## 8. Soundness Verification

### 8.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Ghost start row (keccak/sha256) | #[BITW_START_ONLY_WHEN_SEL] (PR #19875) | PROTECTED |
| Wrong byte operation | #[BYTE_OPERATIONS] lookup | PROTECTED |
| Wrong counter | #[INTEGRAL_TAG_LENGTH] lookup | PROTECTED |
| Skip rows | #[BITW_CTR_DECREMENT] | PROTECTED |
| Wrong accumulation | #[BITW_ACC_REL_*] constraints | PROTECTED |
| FF tag operation | #[INPUT_TAG_CANNOT_BE_FF] | PROTECTED |
| Tag mismatch | #[INPUT_TAGS_SHOULD_MATCH] | PROTECTED |
| Fake error flag | Error checked via zero-check patterns | PROTECTED |

### 8.2 Counter Underflow Protection

From comments (lines 270-277):
> requesting a max value of 31 prevents the acc_ia, acc_ib, acc_ic values to overflow the field
> which represents a potential attack vector.

The `tag_byte_length` is at most 16 (for U128), and the precomputed table bounds this.

### 8.3 Operation ID Propagation

```pil
// bitwise.pil:181-182
#[BITW_OP_ID_REL]
(op_id' - op_id) * (1 - last) = 0;
```

Operation ID remains constant throughout the computation.

---

## 9. Findings

### No Critical Vulnerabilities Found

The bitwise.pil gadget is **SOUND**.

### INFO-1: Multi-Row Byte Decomposition

The gadget processes one byte per row, using counter-controlled iteration. This is efficient for precomputed table size (2^8 entries per operation instead of 2^128).

### INFO-2: PR #19875 Security Fix

The fix addresses a ghost row vulnerability specific to keccak/sha256 invocations while preserving error handling for execution dispatch. This is a subtle but correct fix.

### INFO-3: Dual Invocation Paths

The gadget supports two invocation patterns:
1. From execution with error handling (`start` selector)
2. From keccak/sha256 without error handling (`start_keccak`, `start_sha256` selectors)

This is documented and correctly constrained.

### INFO-4: Potential Optimization Noted

The PIL comments note potential optimizations:
- Alternative implementation with one extra row but simpler constraints
- Recycling of bitwise operations for prefixes
- Tight counter (computing actual byte length vs tag max)

These are documented future considerations, not vulnerabilities.

---

## 10. Conclusion

**Status**: SOUND

The bitwise.pil gadget is **correctly implemented** with:

- Proper counter-controlled byte decomposition
- Sound accumulator reconstruction
- Complete tag error handling (FF and mismatch)
- Correct byte operation lookups
- PR #19875 ghost row fix
- Proper operation ID propagation

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

| Constraint | Purpose |
|------------|---------|
| BITW_SEL_CTR_NON_ZERO | sel ↔ ctr relationship |
| BITW_LAST_FOR_CTR_ONE | last ↔ ctr=1 relationship |
| BITW_CTR_DECREMENT | Counter decrements each row |
| BITW_INIT_A/B/C | Accumulator init on last row |
| BITW_ACC_REL_A/B/C | Accumulator reconstruction |
| BITW_OP_ID_REL | Operation ID propagation |
| INPUT_TAG_CANNOT_BE_FF | FF tag error |
| INPUT_TAGS_SHOULD_MATCH | Tag mismatch error |
| LAST_ON_ERROR | Error forces last=1 |
| RES_TAG_SHOULD_MATCH_INPUT | Output tag = input tag |
| BITW_START_ONLY_WHEN_SEL | Ghost row protection |
| INTEGRAL_TAG_LENGTH | Counter lookup |
| BYTE_OPERATIONS | Byte operation lookup |

## Appendix: Trace Structure

```
Operation Start (start=1, ctr=tag_byte_length)
    │
    ├─ Row 0: Process MSB byte, acc = full value
    │
    ├─ Row 1: ctr--, acc = acc >> 8
    │
    ├─ ...
    │
    └─ Row N-1: ctr=1, last=1, acc = LSB byte
        │
        └─ (computation complete)
```
