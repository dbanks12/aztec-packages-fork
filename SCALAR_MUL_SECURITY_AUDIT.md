# Security Audit: scalar_mul.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `scalar_mul.pil` gadget computes scalar point multiplication over the Grumpkin curve using the double-and-add algorithm. Given point P and scalar s, it computes R = sP.

### Key Characteristics
- Multi-row operation: 254 rows (one per bit of scalar)
- Uses reverse aggregation (start row contains output)
- Precondition: Input P is valid Grumpkin point, scalar is FF
- Lookups to ecc.pil for point operations

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/scalar_mul.pil` | PIL definitions (215 lines) |

---

## 3. Constraint Analysis

### 3.1 Trace Shape

**START_AFTER_LATCH (line 101)**:
```
sel' * (start' - LATCH_CONDITION) = 0
```

**SELECTOR_ON_START_OR_END (line 105)**:
```
(start + end) * (1 - sel) = 0
```

**SELECTOR_CONSISTENCY (line 109)**:
```
(sel' - sel) * (1 - LATCH_CONDITION) = 0
```

### 3.2 Bit Decomposition

**Bit index initialization (line 138)**:
```
start * (bit_idx - 253) = 0
```

**Bit index decrement (line 145)**:
```
sel_not_end * (bit_idx - (bit_idx' + 1)) = 0
```

**End condition (line 141)**:
```
end * bit_idx = 0
```
- `end = 1` only when `bit_idx = 0`

**TO_RADIX lookup (lines 151-155)**:
```
sel { scalar, bit, bit_idx, const_two }
in to_radix.sel { to_radix.value, to_radix.limb, to_radix.limb_index, to_radix.radix }
```
- Verifies each bit is correctly decomposed from scalar

### 3.3 Temp Computation (Doubling)

**End initialization (lines 169-171)**:
```
end * (temp_x - point_x) = 0
end * (temp_y - point_y) = 0
end * (temp_inf - point_inf) = 0
```
- At end, temp = P

**DOUBLE lookup (lines 178-182)**:
```
sel_not_end { temp_x, temp_y, temp_inf, temp_x', temp_y', temp_inf', sel_not_end }
in ecc.sel { ecc.r_x, ecc.r_y, ecc.r_is_inf, ecc.p_x, ecc.p_y, ecc.p_is_inf, ecc.double_op }
```
- Verifies temp = 2 * temp' via ecc.pil

### 3.4 Result Computation (Addition)

**End case (lines 194-196)**:
```
end * (point_x * bit + INFINITY_X * (1 - bit) - res_x) = 0
end * (point_y * bit + INFINITY_Y * (1 - bit) - res_y) = 0
end * ((point_inf - 1) * bit + 1 - res_inf) = 0
```
- If bit=1: res = P; if bit=0: res = O (infinity)

**Conditional pass-through (lines 202-204)**:
```
SHOULD_PASS * (res_x - res_x') = 0
SHOULD_PASS * (res_y - res_y') = 0
SHOULD_PASS * (res_inf - res_inf') = 0
```
Where `SHOULD_PASS = sel_not_end * (1 - bit)`

**ADD lookup (lines 206-210)**:
```
should_add { res_x, res_y, res_inf, res_x', res_y', res_inf', temp_x, temp_y, temp_inf }
in ecc.sel { ecc.r_x, ecc.r_y, ecc.r_is_inf, ecc.p_x, ecc.p_y, ecc.p_is_inf, ecc.q_x, ecc.q_y, ecc.q_is_inf }
```
Where `should_add = sel_not_end * bit`

---

## 4. Soundness Analysis

### 4.1 Attack Surface

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Wrong bit decomposition | TO_RADIX lookup | PROTECTED |
| Wrong doubling | DOUBLE lookup into ecc | PROTECTED |
| Wrong addition | ADD lookup into ecc | PROTECTED |
| Skip bits | Bit index decrement + end condition | PROTECTED |
| Early termination | SELECTOR_CONSISTENCY | PROTECTED |

### 4.2 Reverse Aggregation

The algorithm runs backwards: bit 253 (MSB) at start, bit 0 at end. This allows the start row to contain the final result for caller lookup.

---

## 5. Findings

### No Critical Vulnerabilities Found

The scalar_mul gadget is **SOUND**.

### INFO-1: Fixed 254 Rows

The scalar is always treated as 254 bits (full field element). There's no optimization for smaller scalars.

### INFO-2: Curve Point Precondition

Like ecc.pil, this gadget assumes the input point is on the curve. Callers must ensure this.

---

## 6. Conclusion

**Status**: SOUND

The scalar_mul.pil gadget correctly implements scalar multiplication with:
- Verified bit decomposition via to_radix lookup
- Verified point operations via ecc lookups
- Proper reverse aggregation for efficient caller access
