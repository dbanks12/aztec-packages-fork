# Deep Security Audit: ecc.pil, scalar_mul.pil, ecc_mem.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL files: `pil/vm2/ecc.pil` (188 lines), `pil/vm2/scalar_mul.pil` (215 lines), `pil/vm2/ecc_mem.pil` (225 lines)
- [x] Located dependencies: to_radix.pil, gt.pil, memory.pil, precomputed.pil
- [x] Located callers: address_derivation.pil, execution.pil

### Phase 2: Understanding
- [x] Documented gadget purposes (point add, scalar mul, memory)
- [x] Listed all witnesses
- [x] Listed all constraints
- [x] Understood Grumpkin curve operations

### Phase 3: Soundness
- [x] Verified point addition formulas
- [x] Analyzed edge case handling (infinity, inverse)
- [x] Checked scalar bit decomposition
- [x] Verified on-curve checks

### Phase 4: Completeness
- [x] Reviewed all edge cases
- [x] Checked input propagation
- [x] Verified row count constraints

### Phase 5: Integration
- [x] Verified execution dispatch
- [x] Checked ecc lookup from scalar_mul
- [x] Verified memory permutations

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/ecc.pil` | 188 | Grumpkin point addition (P + Q = R) |
| `pil/vm2/scalar_mul.pil` | 215 | Scalar multiplication (sP = R) |
| `pil/vm2/ecc_mem.pil` | 225 | Memory I/O for ECADD opcode |

---

## 2. Gadget Architecture

### 2.1 Grumpkin Curve

**Equation**: Y² = X³ - 17 (Short Weierstrass form)

**Properties**:
- Forms 2-cycle with BN254
- Base field = BN254 scalar field (and vice versa)
- Point at infinity represented as (0, 0, true)

### 2.2 ecc.pil Purpose

Point addition with all edge cases:
1. **Add** (P ≠ Q, x_match = 0): λ = (q_y - p_y) / (q_x - p_x)
2. **Double** (P = Q): λ = 3p_x² / 2p_y
3. **Inverse** (P = -Q): R = O (infinity)
4. **Infinity cases**: P + O = P, O + Q = Q, O + O = O

### 2.3 scalar_mul.pil Purpose

Double-and-add algorithm for scalar multiplication:
- 254 rows (one per bit of scalar)
- Reverse aggregation (start row contains result)
- Lookups to ecc.pil for double/add operations
- Lookup to to_radix.pil for bit decomposition

### 2.4 ecc_mem.pil Purpose

Memory interface for ECADD opcode:
- On-curve validation
- Bounds checking
- Memory writes for result

---

## 3. ecc.pil Constraints

### 3.1 Operation Selection

```pil
// ecc.pil:67-68
#[OP_CHECK]
sel = double_op + add_op + INVERSE_PRED;
```

Mutually exclusive operations: double, add, or inverse.

### 3.2 Coordinate Matching

```pil
// ecc.pil:91-104
pol X_DIFF = q_x - p_x;
#[X_MATCH]
sel * (X_DIFF * (x_match * (1 - inv_x_diff) + inv_x_diff) - 1 + x_match) = 0;

pol Y_DIFF = q_y - p_y;
#[Y_MATCH]
sel * (Y_DIFF * (y_match * (1 - inv_y_diff) + inv_y_diff) - 1 + y_match) = 0;
```

Zero-check pattern for detecting P = Q.

### 3.3 Double Predicate

```pil
// ecc.pil:124-125
#[DOUBLE_PRED]
double_op - (x_match * y_match) = 0;
```

Double when both x and y match (P = Q).

### 3.4 Lambda Computation

```pil
// ecc.pil:136-140
#[COMPUTED_LAMBDA]
sel * (lambda - (double_op * (3 * p_x * p_x) * inv_2_p_y + add_op * Y_DIFF * inv_x_diff)) = 0;

pol COMPUTED_R_X = lambda * lambda - p_x - q_x;
pol COMPUTED_R_Y = lambda * (p_x - r_x) - p_y;
```

### 3.5 Inverse/Infinity Detection

```pil
// ecc.pil:155-168
pol INVERSE_PRED = x_match * (1 - y_match);  // P = -Q (x match, y differs)
pol BOTH_INF = p_is_inf * q_is_inf;
pol EITHER_INF = p_is_inf + q_is_inf - 2 * BOTH_INF;

#[INFINITY_RESULT]
result_infinity = INVERSE_PRED * BOTH_NON_INF + BOTH_INF;
```

### 3.6 Result Assignment

```pil
// ecc.pil:181-186
#[OUTPUT_X_COORD]
sel * (r_x - (EITHER_INF * (p_is_inf * q_x + q_is_inf * p_x)) - result_infinity * INFINITY_X - use_computed_result * COMPUTED_R_X) = 0;

#[OUTPUT_Y_COORD]
sel * (r_y - (EITHER_INF * (p_is_inf * q_y + q_is_inf * p_y)) - result_infinity * INFINITY_Y - use_computed_result * COMPUTED_R_Y) = 0;

#[OUTPUT_INF_FLAG]
sel * (r_is_inf - result_infinity) = 0;
```

Three cases handled:
1. `use_computed_result = 1`: Normal add/double
2. `EITHER_INF = 1`: One point is infinity, return other
3. `result_infinity = 1`: Return infinity point

---

## 4. scalar_mul.pil Constraints

### 4.1 Trace Shape

```pil
// scalar_mul.pil:136-145
start * (bit_idx - 253) = 0;   // Start at bit 253
end * bit_idx = 0;              // End at bit 0

#[DECREMENT_INDEX]
sel_not_end * (bit_idx - (bit_idx' + 1)) = 0;
```

254 rows, bit_idx decrements from 253 to 0.

### 4.2 Bit Decomposition

```pil
// scalar_mul.pil:151-155
#[TO_RADIX]
sel { scalar, bit, bit_idx, const_two }
in to_radix.sel { to_radix.value, to_radix.limb, to_radix.limb_index, to_radix.radix };
```

Each bit verified against to_radix trace.

### 4.3 Temp Point Doubling

```pil
// scalar_mul.pil:169-182
// At end: temp = point
end * (temp_x - point_x) = 0;
end * (temp_y - point_y) = 0;
end * (temp_inf - point_inf) = 0;

// Otherwise: temp = 2 * temp'
#[DOUBLE]
sel_not_end { temp_x, temp_y, temp_inf, temp_x', temp_y', temp_inf', sel_not_end }
in ecc.sel { ecc.r_x, ecc.r_y, ecc.r_is_inf, ecc.p_x, ecc.p_y, ecc.p_is_inf, ecc.double_op };
```

### 4.4 Result Computation

```pil
// scalar_mul.pil:194-210
// At end: res = bit ? point : infinity
end * (point_x * bit + ecc.INFINITY_X * (1 - bit) - res_x) = 0;

// Otherwise: res = bit ? (res' + temp) : res'
pol SHOULD_PASS = sel_not_end * (1 - bit);
SHOULD_PASS * (res_x - res_x') = 0;

#[ADD]
should_add { res_x, res_y, res_inf, res_x', res_y', res_inf', temp_x, temp_y, temp_inf }
in ecc.sel { ecc.r_x, ecc.r_y, ecc.r_is_inf, ecc.p_x, ecc.p_y, ecc.p_is_inf, ecc.q_x, ecc.q_y, ecc.q_is_inf };
```

---

## 5. ecc_mem.pil Constraints

### 5.1 On-Curve Verification

```pil
// ecc_mem.pil:143-162
// Y^2 = X^3 - 17
pol P_X3 = p_x * p_x * p_x;
pol P_Y2 = p_y * p_y;

#[P_CURVE_EQN]
p_is_on_curve_eqn = sel * (P_Y2 - (P_X3 - 17)) * (1 - p_is_inf);

#[P_ON_CURVE_CHECK]
sel * (p_is_on_curve_eqn * ((1 - sel_p_not_on_curve_err) * (1 - p_is_on_curve_eqn_inv) + p_is_on_curve_eqn_inv) - sel_p_not_on_curve_err) = 0;
```

Zero-check: error if point not on curve (unless infinity).

### 5.2 Infinity Point Normalization

```pil
// ecc_mem.pil:180-183
sel_should_exec * (p_x_n - (1 - p_is_inf) * p_x - p_is_inf * ecc.INFINITY_X) = 0;
sel_should_exec * (p_y_n - (1 - p_is_inf) * p_y - p_is_inf * ecc.INFINITY_Y) = 0;
```

Maps infinity points to (0, 0) for consistent ecc.pil behavior.

### 5.3 Memory Writes (Permutation)

```pil
// ecc_mem.pil:201-223
#[WRITE_MEM_0]
sel_should_exec { execution_clk, space_id, dst_addr[0], res_x, precomputed.zero, sel_should_exec }
is memory.sel_ecc_write[0] { ... };

#[WRITE_MEM_1]
sel_should_exec { ..., dst_addr[1], res_y, ... } is memory.sel_ecc_write[1] { ... };

#[WRITE_MEM_2]
sel_should_exec { ..., dst_addr[2], res_is_inf, ... } is memory.sel_ecc_write[2] { ... };
```

---

## 6. Soundness Verification

### 6.1 Attack Surface Analysis (ecc.pil)

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Wrong lambda | Explicit formula constraint | PROTECTED |
| Skip inverse case | INVERSE_PRED detection via x_match | PROTECTED |
| Wrong infinity handling | BOTH_INF, EITHER_INF flags | PROTECTED |
| Forge result | OUTPUT_X/Y_COORD constraints | PROTECTED |

### 6.2 Attack Surface Analysis (scalar_mul.pil)

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Wrong bit | to_radix.pil lookup | PROTECTED |
| Skip rows | bit_idx decrement + start/end | PROTECTED |
| Wrong double | ecc.pil lookup with double_op | PROTECTED |
| Wrong add | ecc.pil lookup | PROTECTED |
| Input tampering | INPUT_CONSISTENCY_* propagation | PROTECTED |

### 6.3 Attack Surface Analysis (ecc_mem.pil)

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Off-curve point | On-curve check via zero-check | PROTECTED |
| Out-of-bounds write | GT lookup for bounds | PROTECTED |
| Memory forgery | Permutation to memory | PROTECTED |

### 6.4 Critical Security Properties

#### 6.4.1 Point Addition Soundness

The ecc.pil constraints cover all cases:
- `double_op = x_match * y_match` (P = Q)
- `add_op = sel - double_op - INVERSE_PRED` (P ≠ Q, not inverse)
- `INVERSE_PRED = x_match * (1 - y_match)` (P = -Q)

Lambda computed correctly for both double and add.

#### 6.4.2 Scalar Multiplication Row Count

```pil
start * (bit_idx - 253) = 0;
end * bit_idx = 0;
#[DECREMENT_INDEX]
sel_not_end * (bit_idx - (bit_idx' + 1)) = 0;
```

Forces exactly 254 rows (bits 253 down to 0).

#### 6.4.3 Bit Verification

Every bit verified via to_radix lookup:
```pil
#[TO_RADIX]
sel { scalar, bit, bit_idx, const_two }
in to_radix.sel { to_radix.value, to_radix.limb, to_radix.limb_index, to_radix.radix };
```

Cannot forge bits of scalar.

---

## 7. Findings

### No Critical Vulnerabilities Found

All ECC gadgets are **SOUND**.

### INFO-1: Reverse Aggregation

scalar_mul uses reverse aggregation:
> The start row contains the output R (= (res_x, res_y, res_inf))

This is intentional for constraint efficiency.

### INFO-2: Infinity Representation

Point at infinity = (0, 0, true):
```pil
pol INFINITY_X = 0;
pol INFINITY_Y = 0;
```

ecc_mem normalizes infinity inputs to (0, 0) before lookup.

### INFO-3: Double Operation Implication

From comments (ecc.pil:127-130):
> #[DOUBLE_PRED] implies this (since x_match & y_match must imply p_is_inf == q_is_inf for points on the curve)

Extra check added for scalar_mul's #[DOUBLE] lookup.

### INFO-4: Grumpkin/BN254 Relationship

From comments (scalar_mul.pil:22-23):
> Since r < q, we cannot use an invalid scalar here.

The scalar is treated as Fr but is actually Fq, which is safe since Fr < Fq.

---

## 8. Conclusion

**Status**: SOUND

All ECC gadgets are **correctly implemented** with:

**ecc.pil**:
- Complete point addition with all edge cases
- Correct lambda computation for add/double
- Proper infinity and inverse handling
- Zero-check for coordinate matching

**scalar_mul.pil**:
- Correct double-and-add algorithm
- Bit verification via to_radix lookup
- ECC operations via ecc.pil lookups
- Input consistency propagation

**ecc_mem.pil**:
- On-curve verification (Y² = X³ - 17)
- Infinity point normalization
- Permutations for memory writes
- Proper error consolidation

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

### ecc.pil

| Constraint | Purpose |
|------------|---------|
| OP_CHECK | Mutually exclusive operations |
| X_MATCH | Zero-check for x coordinates |
| Y_MATCH | Zero-check for y coordinates |
| DOUBLE_PRED | Double detection |
| COMPUTED_LAMBDA | Lambda formula |
| INFINITY_RESULT | Infinity detection |
| OUTPUT_X/Y_COORD | Result assignment |
| OUTPUT_INF_FLAG | Infinity flag |

### scalar_mul.pil

| Constraint | Purpose |
|------------|---------|
| START_AFTER_LATCH | Trace shape |
| SELECTOR_CONSISTENCY | Active rows |
| INPUT_CONSISTENCY_* | Propagate inputs |
| DECREMENT_INDEX | Bit index counter |
| TO_RADIX | Bit verification |
| DOUBLE | Temp doubling |
| ADD | Result addition |

### ecc_mem.pil

| Constraint | Purpose |
|------------|---------|
| CHECK_DST_ADDR_IN_RANGE | Bounds check |
| P/Q_ON_CURVE_CHECK | On-curve validation |
| INPUT_OUTPUT_ECC_ADD | ECC lookup |
| WRITE_MEM_[0-2] | Memory permutations |

## Appendix: Edge Cases Handled

| Case | x_match | y_match | p_is_inf | q_is_inf | Result |
|------|---------|---------|----------|----------|--------|
| P + Q (different) | 0 | * | 0 | 0 | Computed |
| P + P (double) | 1 | 1 | 0 | 0 | Computed |
| P + (-P) (inverse) | 1 | 0 | 0 | 0 | Infinity |
| O + Q | * | * | 1 | 0 | Q |
| P + O | * | * | 0 | 1 | P |
| O + O | * | * | 1 | 1 | Infinity |
