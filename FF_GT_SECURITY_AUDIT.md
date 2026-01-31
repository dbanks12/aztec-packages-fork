# Security Audit: ff_gt.pil (Field Greater-Than)

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `ff_gt.pil` gadget provides two functionalities:
1. **Field Greater-Than (GT)**: Compare two field elements a > b
2. **Canonical Decomposition (DEC)**: Decompose a field element into two 128-bit limbs while proving it doesn't overflow p

### Key Characteristics
- Multi-row operation: GT requires 5 rows, DEC requires 2 rows
- Decomposes field elements into hi/lo 128-bit limbs
- Proves canonical representation (value < p) via subtraction checks
- Uses shift mechanism to range-check all limbs

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/ff_gt.pil` | PIL constraint definitions (254 lines) |
| `barretenberg/cpp/src/barretenberg/vm2/simulation/gadgets/field_gt.cpp` | Simulation logic |
| `barretenberg/cpp/src/barretenberg/vm2/tracegen/field_gt_trace.cpp` | Trace generation |
| `barretenberg/cpp/src/barretenberg/vm2/constraining/relations/field_gt.test.cpp` | Constraint tests |

---

## 3. Constraint Analysis

### 3.1 Decomposition Constraints

**A_DECOMPOSITION (line 77)**:
```
SEL_START * (a - (a_lo + POW_128 * a_hi)) = 0
```
- Ensures `a = a_lo + 2^128 * a_hi`
- Only active on first row (`SEL_START = sel_gt + sel_dec`)

**B_DECOMPOSITION (line 110)**:
```
sel_gt * (b - (b_lo + POW_128 * b_hi)) = 0
```
- Only active for GT operations (not DEC)

### 3.2 Canonical Representation Checks

The gadget proves `a < p` (and `b < p` for GT) by computing `p - a - 1` and range-checking the result.

**P_SUB_A_LO (line 100)**:
```
SEL_START * (p_sub_a_lo - (P_LO - a_lo - 1 + p_a_borrow * POW_128)) = 0
```

**P_SUB_A_HI (line 102)**:
```
SEL_START * (p_sub_a_hi - (P_HI - a_hi - p_a_borrow)) = 0
```

**Analysis**:
- If `p_a_borrow = 0`: p_lo > a_lo AND p_hi >= a_hi
- If `p_a_borrow = 1`: p_hi > a_hi (compensates for borrow from lo)
- Combined with 128-bit range checks on p_sub_a_{lo,hi}, this proves a < p

### 3.3 GT Result Constraints

**RES_LO (line 202)**:
```
sel_gt * (res_lo - (A_SUB_B_LO * IS_GT + B_SUB_A_LO * (1 - IS_GT))) = 0
```

**RES_HI (line 204)**:
```
sel_gt * (res_hi - (A_SUB_B_HI * IS_GT + B_SUB_A_HI * (1 - IS_GT))) = 0
```

Where:
- `A_SUB_B_LO = a_lo - b_lo - 1 + borrow * POW_128`
- `A_SUB_B_HI = a_hi - b_hi - borrow`
- `B_SUB_A_LO = b_lo - a_lo + borrow * POW_128`
- `B_SUB_A_HI = b_hi - a_hi - borrow`

**Analysis**:
- When `result = 1` (a > b): Uses A_SUB_B formulas, computes a - b - 1
- When `result = 0` (a <= b): Uses B_SUB_A formulas, computes b - a
- Range checks on res_lo, res_hi ensure no underflow

### 3.4 Counter and Shift Mechanism

**RNG_CTR_GT_INIT (line 214)**:
```
sel_gt * (cmp_rng_ctr - 4) = 0
```
GT requires 5 rows total (counter starts at 4, ends at 0).

**RNG_CTR_DEC_INIT (line 218)**:
```
sel_dec * (cmp_rng_ctr - 1) = 0
```
DEC requires 2 rows total.

**RNG_CTR_DECREMENT (line 222)**:
```
cmp_rng_ctr * (cmp_rng_ctr - 1 - cmp_rng_ctr') = 0
```
Counter decrements by 1 each row.

**SHIFT_0-3 (lines 235-246)**:
```
(a_lo' - p_sub_a_lo) * sel_shift_rng = 0;
(a_hi' - p_sub_a_hi) * sel_shift_rng = 0;
...
```
Values shift through the range check columns across rows.

### 3.5 Selector Consistency

**SEL_CONSISTENCY (line 253)**:
```
sel_shift_rng + (sel_gt' + sel_dec') - sel' = 0
```
Ensures `sel` is active for all rows of the operation.

---

## 4. Soundness Analysis

### 4.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Non-canonical decomposition | p_sub checks + range checks | PROTECTED |
| Wrong GT result | res_{lo,hi} range checks | PROTECTED |
| Skip range checks | Counter mechanism | PROTECTED |
| Manipulate intermediate rows | Selector consistency | PROTECTED |

### 4.2 Detailed Soundness Proof

**Claim**: If constraints are satisfied and lookups pass, then `result = 1` iff `a > b`.

**Proof (result = 1 case)**:
1. Decomposition constraints give: a = a_lo + 2^128 * a_hi, b = b_lo + 2^128 * b_hi
2. Range checks on a_lo, a_hi, b_lo, b_hi ensure they're < 2^128
3. Canonical checks (p_sub constraints + range checks) ensure a, b < p
4. RES_LO/RES_HI with IS_GT=1 give: res_lo = a_lo - b_lo - 1 + borrow * 2^128
5. Range check on res_lo means: a_lo - b_lo - 1 + borrow * 2^128 >= 0
6. Range check on res_hi means: a_hi - b_hi - borrow >= 0
7. If borrow = 0: a_lo > b_lo AND a_hi >= b_hi => a > b
8. If borrow = 1: a_hi > b_hi (regardless of lo) => a > b

**Proof (result = 0 case)**: Symmetric, proves a <= b.

---

## 5. Completeness Analysis

### 5.1 Trace Generation Verification

From `field_gt_trace.cpp`:
```cpp
while (cmp_rng_ctr >= 0) {
    write_row();
    row++;
    // shift the limbs to be range checked
    a_limbs.lo = p_sub_a_witness.lo;
    ...
    cmp_rng_ctr--;
}
```

**Verified**:
- Counter correctly initialized based on operation type
- All 10 values for GT (or 4 for DEC) are properly shifted and range-checked
- Selector consistency is maintained

### 5.2 Trace Container Behavior

The trace starts at row 1 (not row 0) because row 0 is reserved:
```cpp
uint32_t row = 1;
```

This matches the test expectation:
```cpp
EXPECT_EQ(trace.get_num_rows(), /*start_row=*/1 + 5);  // GT: 6 rows total
EXPECT_EQ(trace.get_num_rows(), /*start_row=*/1 + 2);  // DEC: 3 rows total
```

---

## 6. Integration Analysis

### 6.1 Callers of ff_gt

| Caller | Lookup Type | Usage |
|--------|-------------|-------|
| `alu.pil:483` | sel_gt | FF comparison in ALU |
| `alu.pil:649` | sel_dec | Canonical decomposition for casting |
| `contract_instance_retrieval.pil:103` | sel_gt | Contract instance validation |
| `tx.pil:691` | sel_gt | Transaction validation |
| `send_l2_to_l1_msg.pil:53` | sel_gt | L2-to-L1 message validation |
| `written_public_data_slots_tree_check.pil` | sel_gt | Public data tree checks |
| `nullifier_check.pil` | sel_gt | Nullifier validation |
| `public_data_check.pil` | sel_gt | Public data validation |
| `retrieved_bytecodes_tree_check.pil` | sel_gt | Bytecode tree checks |

All callers correctly use either `sel_gt` or `sel_dec` selectors (never the raw `sel`).

### 6.2 Dependencies

- **range_check.pil**: Used for 128-bit range checks via A_LO_RANGE, A_HI_RANGE lookups

---

## 7. Test Coverage Assessment

### 7.1 Positive Tests
- Basic comparisons (GT, EQ, LT)
- Edge cases: 0, 2^128, field max (-1)
- Canonical decomposition

### 7.2 Negative Tests
- NegativeManipulatedDecompositions: Tests A_DECOMPOSITION, B_DECOMPOSITION
- NegativeManipulatedComparisonsWithP: Tests P_SUB_A/B constraints
- NegativeLessRangeChecks: Tests counter initialization
- NegativeRangeCheckCtrInitInDec: Tests DEC counter
- NegativeSelectorConsistency: Tests SEL_CONSISTENCY
- NegativeEraseShift: Tests SHIFT_0/1/2/3

---

## 8. Findings

### No Vulnerabilities Found

The ff_gt gadget is **SOUND** and **COMPLETE**:

1. **Sound**: All attack vectors are protected by the constraint system
2. **Complete**: Trace generation correctly produces valid witnesses
3. **Well-integrated**: All callers use correct selectors

---

## 9. Recommendations

### INFO-1: Documentation Enhancement
The comment at line 37 warns "Never invoke FF_GT with `sel` selector". This is good, but could be enforced via additional constraints if desired.

### INFO-2: Field Modulus Constants
The constants P_LO and P_HI (lines 68-69) are hardcoded:
```
P_LO = 53438638232309528389504892708671455233
P_HI = 64323764613183177041862057485226039389
```
These match the BN254 scalar field modulus. Any field change would require updating these constants.

---

## 10. Conclusion

**Status**: SOUND

The ff_gt.pil gadget correctly implements field element comparison and canonical decomposition. The multi-row shift mechanism ensures all necessary range checks are performed. The constraint system is complete and no soundness vulnerabilities were identified.

---

## Appendix: Constraint Index

| Constraint | Line | Purpose |
|------------|------|---------|
| A_DECOMPOSITION | 77 | Decompose a into limbs |
| A_LO_RANGE | 83 | Range check a_lo |
| A_HI_RANGE | 87 | Range check a_hi |
| P_SUB_A_LO | 100 | Canonical check for a |
| P_SUB_A_HI | 102 | Canonical check for a |
| B_DECOMPOSITION | 110 | Decompose b into limbs |
| P_SUB_B_LO | 122 | Canonical check for b |
| P_SUB_B_HI | 124 | Canonical check for b |
| RES_LO | 202 | Result low limb |
| RES_HI | 204 | Result high limb |
| RNG_CTR_GT_INIT | 214 | Initialize counter for GT |
| RNG_CTR_DEC_INIT | 218 | Initialize counter for DEC |
| RNG_CTR_DECREMENT | 222 | Decrement counter |
| RNG_CTR_NON_ZERO | 231 | Counter non-zero selector |
| SHIFT_0 | 236-237 | Shift a_{lo,hi} <- p_sub_a_{lo,hi} |
| SHIFT_1 | 239-240 | Shift p_sub_a <- b |
| SHIFT_2 | 242-243 | Shift b <- p_sub_b |
| SHIFT_3 | 245-246 | Shift p_sub_b <- res |
| SEL_CONSISTENCY | 253 | Selector continuity |
