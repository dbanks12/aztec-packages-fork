# Deep Security Audit: gt.pil & ff_gt.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL files: `pil/vm2/gt.pil` (69 lines), `pil/vm2/ff_gt.pil` (254 lines)
- [x] Located dependency: range_check.pil
- [x] Located callers: alu.pil, execution/gas.pil, sha256.pil, addressing.pil
- [x] Identified dual comparison systems (integer vs field)

### Phase 2: Understanding
- [x] Documented gadget purposes
- [x] Listed all witnesses
- [x] Listed all constraints
- [x] Understood multi-row shift mechanism (ff_gt)

### Phase 3: Soundness
- [x] Verified comparison logic
- [x] Analyzed borrow/carry handling
- [x] Checked canonical decomposition
- [x] Verified range check coverage

### Phase 4: Completeness
- [x] Reviewed preconditions
- [x] Checked edge cases
- [x] Verified shift mechanism

### Phase 5: Integration
- [x] Verified ALU interaction
- [x] Checked gas checking interaction
- [x] Verified SHA256 interaction

---

## Part A: gt.pil (Integer Greater-Than)

### A.1 Purpose

Compares two integers bounded by 2^128 and returns a boolean result.

**Preconditions (documented)**:
> Both inputs must be bounded by p - 1 - 2^128 and the absolute difference must be less than 2^128.

### A.2 Core Constraint

```pil
// gt.pil:49-66
pol A_LTE_B = input_b - input_a;
pol A_GT_B = input_a - input_b - 1;

#[GT_RESULT]
sel * ( (A_GT_B - A_LTE_B) * res + A_LTE_B - abs_diff ) = 0;

#[GT_RANGE]
sel { abs_diff, num_bits } in range_check.sel_gt { range_check.value, range_check.rng_chk_bits };
```

**Analysis**:
- If `res = 1`: `abs_diff = A_GT_B = a - b - 1`
  - Range check proves `a - b - 1 >= 0`, thus `a > b`
- If `res = 0`: `abs_diff = A_LTE_B = b - a`
  - Range check proves `b - a >= 0`, thus `a <= b`

### A.3 Multiple Lookup Selectors

```pil
// gt.pil:27-38
pol commit sel_sha256;
pol commit sel_addressing;
pol commit sel_alu;
pol commit sel_gas;
pol commit sel_others;
(sel_sha256 + sel_addressing + sel_alu + sel_gas + sel_others) * (1 - sel) = 0;
```

**Analysis**: Different callers use different selectors for inverse generation decoupling.

### A.4 Soundness Verification

| Property | Protection |
|----------|------------|
| `res = 1` valid | Range check proves `a - b - 1 >= 0` |
| `res = 0` valid | Range check proves `b - a >= 0` |
| Bounded abs_diff | `num_bits <= 128` enforced by range_check |
| Input bounds | Caller responsibility (documented precondition) |

---

## Part B: ff_gt.pil (Field Greater-Than)

### B.1 Purpose

Compares two field elements using canonical decomposition into 128-bit limbs.

**Dual functionality**:
1. `sel_gt`: Full field comparison (a > b)
2. `sel_dec`: Canonical decomposition only (a = a_lo + 2^128 * a_hi, a < p)

### B.2 Multi-Row Structure

```
| Row | sel | sel_gt | cmp_rng_ctr | a_lo/a_hi content |
|-----|-----|--------|-------------|-------------------|
| 0   |  1  |   1    |      4      | a_lo, a_hi        | ← lookup here
| 1   |  1  |   0    |      3      | p_sub_a_lo, p_sub_a_hi |
| 2   |  1  |   0    |      2      | b_lo, b_hi        |
| 3   |  1  |   0    |      1      | p_sub_b_lo, p_sub_b_hi |
| 4   |  1  |   0    |      0      | res_lo, res_hi    |
```

5 rows for GT, 2 rows for canonical decomposition.

### B.3 A Decomposition

```pil
// ff_gt.pil:76-77
#[A_DECOMPOSITION]
SEL_START * (a - (a_lo + POW_128 * a_hi)) = 0;
```

### B.4 Canonical Decomposition Proof

```pil
// ff_gt.pil:99-102
pol P_LO = 53438638232309528389504892708671455233; // Lower 128 bits of p
pol P_HI = 64323764613183177041862057485226039389; // Upper 128 bits of p

#[P_SUB_A_LO]
SEL_START * (p_sub_a_lo - (P_LO - a_lo - 1 + p_a_borrow * POW_128)) = 0;
#[P_SUB_A_HI]
SEL_START * (p_sub_a_hi - (P_HI - a_hi - p_a_borrow)) = 0;
```

**Analysis**: Proves `a < p` by showing `p - a - 1 >= 0`:
- If `p_a_borrow = 0`: `p_lo > a_lo` and `p_hi >= a_hi`
- If `p_a_borrow = 1`: `p_lo <= a_lo` and `p_hi > a_hi`

Range checks on `p_sub_a_lo` and `p_sub_a_hi` complete the proof.

### B.5 GT Operation

```pil
// ff_gt.pil:134-140
pol A_SUB_B_LO = a_lo - b_lo - 1 + borrow * POW_128;
pol A_SUB_B_HI = a_hi - b_hi - borrow;

pol B_SUB_A_LO = b_lo - a_lo + borrow * POW_128;
pol B_SUB_A_HI = b_hi - a_hi - borrow;

#[RES_LO]
sel_gt * (res_lo - (A_SUB_B_LO * IS_GT + B_SUB_A_LO * (1 - IS_GT))) = 0;
#[RES_HI]
sel_gt * (res_hi - (A_SUB_B_HI * IS_GT + B_SUB_A_HI * (1 - IS_GT))) = 0;
```

**Analysis** (from detailed comments lines 145-198):

**LTE case** (`result = 1`, `IS_GT = 0`):
- `res_lo = b_lo - a_lo + borrow * 2^128`
- `res_hi = b_hi - a_hi - borrow`
- Range checks prove `b >= a`

**LT case** (swapped inputs, `IS_GT = 1`):
- `res_lo = y_lo - x_lo - 1 + borrow * 2^128`
- `res_hi = y_hi - x_hi - borrow`
- Range checks prove `y > x`, thus `x < y`

### B.6 Shift Mechanism for Range Checks

```pil
// ff_gt.pil:221-246
#[RNG_CTR_DECREMENT]
cmp_rng_ctr * (cmp_rng_ctr - 1 - cmp_rng_ctr') = 0;

#[SHIFT_0]
(a_lo' - p_sub_a_lo) * sel_shift_rng = 0;
(a_hi' - p_sub_a_hi) * sel_shift_rng = 0;
#[SHIFT_1]
(p_sub_a_lo' - b_lo) * sel_shift_rng = 0;
(p_sub_a_hi' - b_hi) * sel_shift_rng = 0;
// ... SHIFT_2, SHIFT_3
```

**Analysis**: Values are shifted into `a_lo'` and `a_hi'` columns which have range checks (`#[A_LO_RANGE]`, `#[A_HI_RANGE]`). This allows 2 range checks per row, requiring 5 rows total for GT (10 values to check).

### B.7 Selector Consistency

```pil
// ff_gt.pil:252-253
#[SEL_CONSISTENCY]
sel_shift_rng + (sel_gt' + sel_dec') - sel' = 0;
```

**Analysis**: `sel` must be on for the full computation:
- First row: `sel_gt' = 1` or `sel_dec' = 1`
- Subsequent rows: `sel_shift_rng = 1`

---

## C. Soundness Verification

### C.1 Attack Surface Analysis (gt.pil)

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Forge comparison result | Range check on abs_diff | PROTECTED |
| Input overflow | Caller precondition | CALLER RESPONSIBILITY |
| Multiple selectors active | Sum constraint | PROTECTED |

### C.2 Attack Surface Analysis (ff_gt.pil)

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Non-canonical decomposition | P_SUB_A_* constraints + range checks | PROTECTED |
| Wrong limb decomposition | A_DECOMPOSITION + range checks | PROTECTED |
| Borrow manipulation | Boolean constraint + range checks | PROTECTED |
| Skip range check rows | sel_shift_rng ↔ cmp_rng_ctr relationship | PROTECTED |
| Wrong result | res_lo/res_hi range checks | PROTECTED |

### C.3 Critical Security Property: Complete Range Check Coverage

For GT operation, 10 128-bit values must be range checked:
1. a_lo, a_hi (row 0)
2. p_sub_a_lo, p_sub_a_hi (row 1)
3. b_lo, b_hi (row 2)
4. p_sub_b_lo, p_sub_b_hi (row 3)
5. res_lo, res_hi (row 4)

The shift mechanism ensures all 10 values flow through the `a_lo`/`a_hi` range check lookups.

---

## D. Findings

### No Critical Vulnerabilities Found

Both gt.pil and ff_gt.pil gadgets are **SOUND**.

### INFO-1: Precondition for gt.pil

The gt.pil gadget has a documented precondition:
> Both inputs must be bounded by 2^128

This is the caller's responsibility. The ALU ensures this via memory tag checks (U128 or smaller).

### INFO-2: Multi-Row Structure for ff_gt.pil

The ff_gt gadget uses a clever shift mechanism to perform 10 range checks using only 2 range check columns. This is space-efficient but requires careful coordination between rows.

### INFO-3: Dual Functionality (ff_gt.pil)

The ff_gt gadget supports two operations:
1. `sel_gt`: Full field comparison
2. `sel_dec`: Canonical decomposition (used by alu.pil for TRUNCATE)

These are mutually exclusive due to different `cmp_rng_ctr` values.

### INFO-4: Detailed Correctness Proof

The ff_gt.pil file contains extensive comments (lines 145-198) proving the soundness of the comparison logic for both LT and LTE operations, considering both borrow cases.

---

## E. Conclusion

**Status**: SOUND

Both gadgets are **correctly implemented** with:

**gt.pil**:
- Simple difference-based comparison
- Single range check proves result correctness
- Multiple selector support for different callers

**ff_gt.pil**:
- Sound canonical decomposition with `p - a - 1 >= 0` proof
- Correct multi-limb comparison with borrow handling
- Complete range check coverage via shift mechanism
- Selector consistency across multi-row computation

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

### gt.pil

| Constraint | Purpose |
|------------|---------|
| GT_RESULT | Core comparison logic |
| GT_RANGE | Range check abs_diff |

### ff_gt.pil

| Constraint | Purpose |
|------------|---------|
| A_DECOMPOSITION | a = a_lo + 2^128 * a_hi |
| P_SUB_A_LO/HI | Prove a < p |
| B_DECOMPOSITION | b = b_lo + 2^128 * b_hi |
| P_SUB_B_LO/HI | Prove b < p |
| RES_LO/HI | Compute comparison result |
| A_LO/HI_RANGE | Range check limbs |
| RNG_CTR_DECREMENT | Counter for shift rows |
| RNG_CTR_NON_ZERO | sel_shift_rng ↔ counter |
| SHIFT_0/1/2/3 | Shift values for range checks |
| SEL_CONSISTENCY | Active rows coverage |

## Appendix: Range Check Values for GT

```
Row 0: a_lo, a_hi (inputs from lookup)
Row 1: p_sub_a_lo, p_sub_a_hi (shifted from row 0)
Row 2: b_lo, b_hi (shifted from row 1)
Row 3: p_sub_b_lo, p_sub_b_hi (shifted from row 2)
Row 4: res_lo, res_hi (shifted from row 3)
```
