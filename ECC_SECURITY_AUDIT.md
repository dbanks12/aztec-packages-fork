# Security Audit: ecc.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `ecc.pil` gadget implements point addition over the Grumpkin curve (Y^2 = X^3 - 17 in Short Weierstrass form). Given two points P and Q, it computes R = P + Q.

### Key Characteristics
- Single-row operation per computation
- Supports: point addition, point doubling, infinity handling
- Precondition: Inputs P, Q are valid Grumpkin curve points
- Point at infinity represented as (0, 0, true)

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/ecc.pil` | PIL constraint definitions (188 lines) |

---

## 3. Constraint Analysis

### 3.1 Operation Selection

**OP_CHECK (line 68)**:
```
sel = double_op + add_op + INVERSE_PRED
```
- Three mutually exclusive cases: double, add, inverse

**DOUBLE_PRED (line 125)**:
```
double_op - (x_match * y_match) = 0
```
- `double_op = 1` iff P == Q (same x and y coordinates)

### 3.2 Coordinate Matching

**X_MATCH (line 95)**:
```
sel * (X_DIFF * (x_match * (1 - inv_x_diff) + inv_x_diff) - 1 + x_match) = 0
```
- `x_match = 1` iff `q_x = p_x`

**Y_MATCH (line 104)**:
```
sel * (Y_DIFF * (y_match * (1 - inv_y_diff) + inv_y_diff) - 1 + y_match) = 0
```
- `y_match = 1` iff `q_y = p_y`

### 3.3 Lambda Computation

**COMPUTED_LAMBDA (line 138)**:
```
sel * (lambda - (double_op * (3 * p_x * p_x) * inv_2_p_y + add_op * Y_DIFF * inv_x_diff)) = 0
```
- Double: lambda = 3*p_x^2 / (2*p_y)
- Add: lambda = (q_y - p_y) / (q_x - p_x)

### 3.4 Result Computation

**Standard formula (lines 139-140)**:
```
COMPUTED_R_X = lambda^2 - p_x - q_x
COMPUTED_R_Y = lambda * (p_x - r_x) - p_y
```

### 3.5 Edge Cases

**INVERSE_PRED (line 155)**:
```
INVERSE_PRED = x_match * (1 - y_match)
```
- True when P = -Q (same x, opposite y)

**INFINITY_RESULT (line 168)**:
```
result_infinity = INVERSE_PRED * BOTH_NON_INF + BOTH_INF
```
- Result is infinity when P = -Q or both inputs are infinity

### 3.6 Output Assignment

**OUTPUT_X_COORD / OUTPUT_Y_COORD (lines 182-184)**:
```
sel * (r_x - (EITHER_INF * (p_is_inf * q_x + q_is_inf * p_x))
           - result_infinity * INFINITY_X
           - use_computed_result * COMPUTED_R_X) = 0
```
Three cases:
1. `use_computed_result`: Normal addition/doubling
2. `result_infinity`: Return point at infinity
3. `EITHER_INF`: Return the non-infinity input

---

## 4. Soundness Analysis

### 4.1 Attack Surface

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Wrong case selection | OP_CHECK mutual exclusion | PROTECTED |
| Wrong lambda | COMPUTED_LAMBDA | PROTECTED |
| Wrong result | OUTPUT constraints | PROTECTED |
| Infinity handling | EITHER_INF + result_infinity | PROTECTED |
| Division by zero | Implicit in curve properties | PROTECTED |

### 4.2 Curve Point Precondition

The gadget assumes inputs are valid curve points. This is NOT enforced here - callers (e.g., ecc_mem.pil) must ensure it.

---

## 5. Findings

### No Critical Vulnerabilities Found

The ecc gadget is **SOUND**.

### INFO-1: No On-Curve Verification

The gadget does not verify that input points are on the curve. This is documented as a precondition and must be ensured by callers.

### INFO-2: Degree Reduction via Commits

The gadget commits to intermediate values (`lambda`, `use_computed_result`, `result_infinity`) to keep constraint degree <= 6.

---

## 6. Conclusion

**Status**: SOUND

The ecc.pil gadget correctly implements Grumpkin point addition with:
- Proper case analysis for add/double/inverse
- Correct infinity point handling
- Standard Short Weierstrass formulas
