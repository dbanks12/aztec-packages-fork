# Security Audit: sha256.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `sha256.pil` gadget implements the SHA-256 compression function. It operates on 65 rows per block (64 compression rounds + 1 output row).

### Key Characteristics
- Multi-row operation: 65 rows per compression
- Implements standard SHA-256 round function
- Uses bitwise gadget for XOR/AND operations
- Uses gt gadget for modular arithmetic range checks
- All inputs assumed 32-bit range-checked by caller (sha256_mem.pil)

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/sha256.pil` | PIL constraint definitions (601 lines) |
| `barretenberg/cpp/pil/vm2/sha256_mem.pil` | Memory-aware wrapper |

---

## 3. Constraint Analysis

### 3.1 Round Counter

**Round initialization and decrement (lines 80-82)**:
```
start * (rounds_remaining - NUM_ROUNDS) + perform_round * (rounds_remaining - rounds_remaining' - 1) = 0
```
- Counter starts at 64, decrements each round

**Latch detection (line 85)**:
```
SEL_NO_ERR * (rounds_remaining * (latch * (1 - rounds_remaining_inv) + rounds_remaining_inv) - 1 + latch) = 0
```
- `latch = 1` iff `rounds_remaining = 0`

### 3.2 Message Schedule (W computation)

For rounds 16-63, W is computed from previous W values:
```
s0 := (w[i-15] rotr 7) xor (w[i-15] rotr 18) xor (w[i-15] rshift 3)
s1 := (w[i-2] rotr 17) xor (w[i-2] rotr 19) xor (w[i-2] rshift 10)
w[i] := w[i-16] + s0 + w[i-7] + s1
```

**Rotation correctness** (see NOTE_ON_ROTATIONS):
- Decompose X = lhs * 2^a + rhs
- Result Y = rhs * 2^(32-a) + lhs
- Only rhs < 2^a needs explicit range check

### 3.3 Compression Function

**S1 computation (lines 298-354)**:
```
S_1 = (e rotr 6) xor (e rotr 11) xor (e rotr 25)
```

**CH computation (lines 356-378)**:
```
CH = (e and f) xor ((not e) and g)
```

**S0 computation (lines 389-444)**:
```
S_0 = (a rotr 2) xor (a rotr 13) xor (a rotr 22)
```

**MAJ computation (lines 447-476)**:
```
MAJ = (a and b) xor (a and c) xor (b and c)
```

### 3.4 State Update

```
h' = g
g' = f
f' = e
e' = (d + TMP_1) mod 2^32
d' = c
c' = b
b' = a
a' = (S0 + MAJ + TMP_1) mod 2^32
```

### 3.5 Final Output

**Output addition (lines 519-534)**:
```
OUT_A = a + init_a  (mod 2^32)
OUT_B = b + init_b  (mod 2^32)
...
```

All modular additions are verified via decomposition into lhs/rhs and range checks.

---

## 4. Soundness Analysis

### 4.1 Attack Surface

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Wrong rotation | Decomposition + range checks | PROTECTED |
| Wrong XOR/AND | Bitwise lookup | PROTECTED |
| Skip rounds | Counter mechanism | PROTECTED |
| Overflow mod 2^32 | lhs/rhs decomposition + gt lookups | PROTECTED |
| Wrong output | Final addition constraints | PROTECTED |

### 4.2 Bitwise Dependency

SHA-256 heavily relies on the bitwise gadget for XOR and AND operations. The bitwise gadget's ghost row vulnerability (fixed in PR #19875) would have critically affected SHA-256 security.

---

## 5. Findings

### No Critical Vulnerabilities Found

The sha256 gadget is **SOUND**.

### INFO-1: Large Constraint Count

The gadget has numerous rotation decomposition constraints (12+ different rotation amounts). Each requires:
- Decomposition constraint
- Range check for the smaller limb
- This is correct but adds significant constraint complexity

---

## 6. Conclusion

**Status**: SOUND

The sha256.pil gadget correctly implements SHA-256 compression with:
- Proper round counter management
- Correct rotation and shift decompositions
- Bitwise operations via proven lookup
- Modular arithmetic via decomposition and range checks
