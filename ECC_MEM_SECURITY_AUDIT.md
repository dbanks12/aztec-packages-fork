# Security Audit: ecc_mem.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `ecc_mem.pil` gadget handles memory writes for the ECADD opcode. It verifies that input points lie on the Grumpkin curve, dispatches to the ECC subtrace for point addition, and writes the result to memory.

### Key Characteristics
- Single-row operation
- On-curve verification: Y^2 = X^3 - 17 (Grumpkin)
- Infinity point remapping to (0, 0) for ECC compatibility
- Writes 3 values: res_x (FF), res_y (FF), res_is_inf (U1)

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/ecc_mem.pil` | PIL constraint definitions (225 lines) |

---

## 3. Constraint Analysis

### 3.1 Address Constraints

**WRITE_INCR_DST_ADDR (lines 110-111)**:
```
dst_addr[1] = sel * (dst_addr[0] + 1)
dst_addr[2] = sel * (dst_addr[0] + 2)
```

### 3.2 Out-of-Bounds Checking

**CHECK_DST_ADDR_IN_RANGE (line 128)**:
```
sel { dst_addr[2], max_mem_addr, sel_dst_out_of_range_err }
in gt.sel_others { gt.input_a, gt.input_b, gt.res };
```
- Checks `dst_addr[2] > AVM_HIGHEST_MEM_ADDRESS`

### 3.3 On-Curve Verification

**P_CURVE_EQN (line 147)**:
```
p_is_on_curve_eqn = sel * (P_Y2 - (P_X3 - 17)) * (1 - p_is_inf)
```
Where `P_X3 = p_x * p_x * p_x` and `P_Y2 = p_y * p_y`.

**P_ON_CURVE_CHECK (line 151)**:
```
sel * (p_is_on_curve_eqn * ((1 - sel_p_not_on_curve_err) * (1 - p_is_on_curve_eqn_inv) + p_is_on_curve_eqn_inv) - sel_p_not_on_curve_err) = 0
```
- Standard zero-check: `sel_p_not_on_curve_err = 1` iff `p_is_on_curve_eqn != 0`

**Q_CURVE_EQN (line 158)** and **Q_ON_CURVE_CHECK (line 162)**:
- Same pattern for point Q

### 3.4 Error Consolidation

**err (line 165)**:
```
err = 1 - (1 - sel_dst_out_of_range_err) * (1 - sel_p_not_on_curve_err) * (1 - sel_q_not_on_curve_err)
```

### 3.5 Infinity Point Handling

**Infinity remapping (lines 180-183)**:
```
sel_should_exec * (p_x_n - (1 - p_is_inf) * p_x - p_is_inf * ecc.INFINITY_X) = 0
sel_should_exec * (p_y_n - (1 - p_is_inf) * p_y - p_is_inf * ecc.INFINITY_Y) = 0
```
- Maps infinity points to (0, 0) for ECC compatibility

### 3.6 ECC Dispatch

**INPUT_OUTPUT_ECC_ADD (line 186)**:
```
sel_should_exec {
    p_x_n, p_y_n, p_is_inf,
    q_x_n, q_y_n, q_is_inf,
    res_x, res_y, res_is_inf
} in ecc.sel { ... };
```

### 3.7 Memory Writes

**WRITE_MEM_0 through WRITE_MEM_2 (lines 201-223)**:
- Writes res_x with tag FF (0)
- Writes res_y with tag FF (0)
- Writes res_is_inf with tag U1 (1)

---

## 4. Soundness Analysis

### 4.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Output address overflow | CHECK_DST_ADDR_IN_RANGE + gt lookup | PROTECTED |
| Point not on curve (P) | P_ON_CURVE_CHECK | PROTECTED |
| Point not on curve (Q) | Q_ON_CURVE_CHECK | PROTECTED |
| Wrong ECC result | INPUT_OUTPUT_ECC_ADD lookup to ecc.pil | PROTECTED |
| Ghost memory writes | sel_should_exec = sel * (1 - err) | PROTECTED |
| Infinity bypass | Explicit remapping + ecc.pil constraints | PROTECTED |

### 4.2 Critical Constraints Verified

1. **Curve Equation**: Y^2 = X^3 - 17 verified for non-infinity points
2. **Infinity Handling**: Infinity points bypass curve check (correctly so)
3. **ECC Integration**: Result comes from verified ECC gadget
4. **Tag Correctness**: Output tags hardcoded in permutations

### 4.3 Preconditions

The gadget has the following preconditions (verified by execution.pil):
- Input coordinates are tag-checked (FF for x, y; U1 for is_inf)
- p_is_inf and q_is_inf are boolean (verified by ecc.pil lookup)

---

## 5. Findings

### No Critical Vulnerabilities Found

The ecc_mem gadget is **SOUND**.

### INFO-1: Infinity Point Coordinates

Infinity points pass the on-curve check due to `(1 - p_is_inf)` factor. Their coordinates are remapped to `ecc.INFINITY_X` and `ecc.INFINITY_Y` (both 0) before dispatch to ECC.

### INFO-2: Result Infinity Coordinates

By ecc.pil constraints (`#[OUTPUT_X_COORD]` and `#[OUTPUT_Y_COORD]`), when result is infinity, coordinates are forced to (0, 0). This is written correctly to memory.

---

## 6. Conclusion

**Status**: SOUND

The ecc_mem gadget correctly implements ECADD memory operations with:
- Grumpkin curve equation verification
- Proper infinity point handling
- Address bounds checking
- Integration with ECC subtrace for correct addition

The constraint system is complete and no soundness vulnerabilities were identified.
