# Security Audit: keccakf1600.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `keccakf1600.pil` gadget implements the Keccak-f[1600] permutation used in SHA-3 and Keccak256. It operates on a 25 x 64-bit state (1600 bits) and applies 24 rounds of the Keccak round function.

### Key Characteristics
- Multi-row operation: 24 rows per permutation (1 round per row)
- Memory-aware via keccak_memory.pil
- Implements theta, rho, pi, chi, and iota sub-functions
- Heavily uses bitwise gadget for XOR/AND operations

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/keccakf1600.pil` | PIL definitions (~1800 lines) |
| `barretenberg/cpp/pil/vm2/keccak_memory.pil` | Memory I/O handling |

---

## 3. Constraint Analysis

### 3.1 Round Counter

**Round initialization (line 96)**:
```
start * (round - 1) = 0
```

**Round increment (line 129)**:
```
sel * (1 - LATCH_CONDITION) * (round' - round - 1) = 0
```

**Selector-round linkage (line 101)**:
```
round * ((1 - sel) * (1 - round_inv) + round_inv) - sel = 0
```
- `sel = 1` iff `round != 0`

### 3.2 Theta Function

The theta function computes column parity and applies it to the state:

1. **Column XOR** (20 lookups): XOR all 5 elements per column
2. **Rotation by 1** (5 constraints): Rotate column sums left by 1 bit
3. **Combined XOR** (5 lookups): XOR adjacent columns
4. **State update** (25 lookups): XOR each state word with result

**MSB Boolean constraint (lines 352-358)**:
```
theta_xor_row_msb_0 * (1 - theta_xor_row_msb_0) = 0
theta_xor_row_0 = 2**63 * theta_xor_row_msb_0 + theta_xor_row_low63_0
theta_xor_row_rotl1_0 = 2 * theta_xor_row_low63_0 + theta_xor_row_msb_0
```

### 3.3 Rho and Pi Functions

Rho (rotation) and Pi (permutation) are applied together:
- Each of 25 state words is rotated by a specific amount
- Words are permuted to new positions

**Rotation correctness**: Based on the rotation proof (lines 139-165):
- Decompose X = hi * 2^a + low
- Rotated Y = low * 2^(64-a) + hi
- Only need to range-check the smaller limb

### 3.4 Chi Function

Chi applies the non-linear mixing operation:
```
chi[i] = state[i] XOR ((NOT state[i+1]) AND state[i+2])
```

Uses AND and XOR lookups into bitwise gadget.

### 3.5 Iota Function

Iota XORs a round constant into state[0][0]:
```
state_iota_00 = state_chi_00 XOR round_constant[round]
```

---

## 4. Soundness Analysis

### 4.1 Attack Surface

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Wrong XOR/AND | Bitwise lookup | PROTECTED |
| Wrong rotation | Decomposition + range check | PROTECTED |
| Skip rounds | Round counter + selector | PROTECTED |
| Wrong round constant | Precomputed lookup | PROTECTED |
| Memory corruption | keccak_memory permutation | PROTECTED |

### 4.2 Critical Dependency: Bitwise Gadget

Keccakf1600 makes 100+ lookups per round into `bitwise.start_keccak`. The ghost row vulnerability fixed in PR #19875 was **critical** for this gadget:

**Before fix**: Attacker could forge any XOR result, completely breaking Keccak security.

**After fix**: All XOR/AND operations are properly constrained via bitwise lookup.

### 4.3 Rotation Verification

The rotation proof (lines 139-165) shows that constraining:
1. X < 2^64 (via bitwise input)
2. Y < 2^64 (via bitwise output)
3. low < 2^a (via range check)

Is sufficient to prove correct rotation without explicitly checking hi < 2^b.

---

## 5. Findings

### No Critical Vulnerabilities Found

The keccakf1600 gadget is **SOUND**.

### INFO-1: Large Constraint Count

Each round requires 100+ bitwise lookups. This is inherent to the Keccak algorithm structure.

### INFO-2: Memory Integration

The gadget uses permutation (`is`) for memory operations, preventing fake memory insertions.

---

## 6. Conclusion

**Status**: SOUND

The keccakf1600.pil gadget correctly implements the Keccak-f[1600] permutation with:
- Proper round function implementation (theta, rho, pi, chi, iota)
- Verified bitwise operations via lookup
- Correct rotation decomposition and range checking
- Secure memory integration via permutation

The security critically depends on the bitwise gadget's ghost row fix (PR #19875).
