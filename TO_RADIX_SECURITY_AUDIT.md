# Security Audit: to_radix.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `to_radix.pil` gadget decomposes a field element into limbs of an arbitrary radix (2-256). Key features:
- Little-endian decomposition with accumulator verification
- Overflow protection against field modulus p
- Support for padding limbs beyond the strictly needed count
- Comprehensive error handling in the `to_radix_mem.pil` variant

### Key Characteristics
- Multi-row operation: One row per limb
- Radix range: 2 to 256
- Limb range: 0 to radix-1 (8-bit range checks)
- Overflow protection via comparison against p's decomposition

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/to_radix.pil` | PIL constraint definitions (226 lines) |
| `barretenberg/cpp/src/barretenberg/vm2/tracegen/to_radix_trace.cpp` | Trace generation |
| `barretenberg/cpp/src/barretenberg/vm2/constraining/relations/to_radix.test.cpp` | Constraint tests (1116 lines) |

---

## 3. Constraint Analysis

### 3.1 Lifecycle Constraints

**START_AFTER_LATCH (line 52)**:
```
sel' * (start' - LATCH_CONDITION) = 0
```
Where `LATCH_CONDITION = end + precomputed.first_row`.

**SELECTOR_ON_START (line 56)**:
```
start * (1 - sel) = 0
```

**SELECTOR_CONSISTENCY (line 59)**:
```
(sel' - sel) * (1 - LATCH_CONDITION) = 0
```

### 3.2 Exponentiation Constraints

**Exponent initialization (line 76)**:
```
start * (exponent - 1) = 0
```

**Exponent progression (line 78)**:
```
not_end * not_padding_limb' * (exponent * radix - exponent') = 0
```

**Padding limb progression (line 82)**:
```
not_end * ((0 - not_padding_limb) * is_unsafe_limb + not_padding_limb - not_padding_limb') = 0
```

**Padding exponent zero (line 85)**:
```
(1 - not_padding_limb) * exponent = 0
```

### 3.3 Accumulation Constraints

**Limb index initialization (line 95)**:
```
start * (limb_index - 0) = 0
```

**Limb index increment (line 98)**:
```
not_end * (limb_index + 1 - limb_index') = 0
```

**Limb less than radix (line 109)**:
```
sel * (radix - 1 - limb - limb_radix_diff) = 0
```

**Accumulator initialization (line 119)**:
```
start * (acc - limb) = 0
```

**Accumulator progression (line 121)**:
```
not_end * (acc + exponent' * limb' - acc') = 0
```

**Found detection (line 126)**:
```
sel * (REM * (found * (1 - rem_inverse) + rem_inverse) - 1 + found) = 0
```
Where `REM = value - acc`.

**Found implies zero limbs (line 129)**:
```
not_end * found * limb' = 0
```

**End requires found (line 132)**:
```
(1 - found) * end = 0
```

### 3.4 Overflow Protection

**FETCH_SAFE_LIMBS (lines 140-143)**:
```
start { radix, safe_limbs } in precomputed.sel_to_radix_p_limb_counts { ... }
```

**Padding limb zero (line 149)**:
```
(1 - not_padding_limb) * limb = 0
```

**Padding p_limb zero (line 151)**:
```
(1 - not_padding_limb) * p_limb = 0
```

**Unsafe limb detection (line 156)**:
```
sel * (safety_diff * (is_unsafe_limb * (1 - safety_diff_inverse) + safety_diff_inverse) - 1 + is_unsafe_limb) = 0
```

**FETCH_P_LIMB (lines 162-165)**:
```
not_padding_limb { radix, limb_index, p_limb } in precomputed.sel_p_decomposition { ... }
```

**acc_under_p initialization (line 207)**:
```
start * (acc_under_p - limb_lt_p) = 0
```

**acc_under_p progression (line 209)**:
```
not_end * ((acc_under_p - limb_lt_p') * limb_eq_p' + limb_lt_p' - acc_under_p') = 0
```

**OVERFLOW_CHECK (line 213)**:
```
is_unsafe_limb * (1 - acc_under_p) = 0
```

### 3.5 Constant Consistency

**CONSTANT_CONSISTENCY_RADIX (line 219)**:
```
not_end * (radix - radix') = 0
```

**CONSTANT_CONSISTENCY_VALUE (line 222)**:
```
not_end * (value - value') = 0
```

**CONSTANT_CONSISTENCY_SAFE_LIMBS (line 225)**:
```
not_end * (safe_limbs - safe_limbs') = 0
```

---

## 4. Soundness Analysis

### 4.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Value >= p | OVERFLOW_CHECK + acc_under_p | PROTECTED |
| Limb >= radix | limb_radix_diff + range check | PROTECTED |
| Wrong accumulator | acc constraints + found check | PROTECTED |
| Skip limbs | limb_index increment | PROTECTED |
| Change radix mid-computation | CONSTANT_CONSISTENCY_RADIX | PROTECTED |
| Change value mid-computation | CONSTANT_CONSISTENCY_VALUE | PROTECTED |

### 4.2 Overflow Protection Deep Dive

The overflow protection ensures the decomposed value is canonical (< p):

1. `safe_limbs` is the index where overflow could occur (looked up from precomputed)
2. For each limb, compare `limb` vs `p_limb` (p's decomposition at that index)
3. Track `acc_under_p`: true if we've seen a limb strictly less than p_limb
4. At `is_unsafe_limb` (index == safe_limbs), require `acc_under_p = 1`

**Logic**:
- If all limbs == p's limbs up to safe_limbs, value = p (invalid, caught by overflow check)
- If any limb < p_limb, acc_under_p becomes true and stays true
- If any limb > p_limb before safe_limbs, the accumulator would exceed p anyway

### 4.3 Limb Comparison Implementation

The gadget implements its own 8-bit limb comparison instead of using the gt gadget:

```
pol LIMB_LT_P = p_limb - limb - 1;
pol LIMB_GT_P = limb - p_limb - 1;
pol LIMB_EQ_P = (limb - p_limb) * 256;
```

The EQ case multiplies by 256 to ensure only 0 passes the 8-bit range check.

---

## 5. Completeness Analysis

### 5.1 Trace Generation

From `to_radix_trace.cpp`:
```cpp
for (uint32_t i = 0; i < event.limbs.size(); ++i) {
    bool is_padding = i > safe_limbs;
    if (limb != p_limb) {
        acc_under_p = limb < p_limb;
    }
    // ... fill row
}
```

**Verified**:
- Correct safe_limbs lookup per radix
- acc_under_p properly tracks comparison state
- Padding limbs correctly handled

### 5.2 Edge Cases

- **Value = 0**: Produces all-zero limbs, found = true on first limb
- **Value = p-1**: Maximum valid value, overflow check passes
- **Value = p**: Would fail OVERFLOW_CHECK (tested in NegativeOverflowCheck)
- **Padding limbs**: Allowed beyond safe_limbs, must be zero

---

## 6. Integration Analysis

### 6.1 Lookups

| Lookup | Purpose |
|--------|---------|
| LIMB_RANGE | Range check limb < 256 |
| LIMB_LESS_THAN_RADIX_RANGE | Range check limb_radix_diff |
| FETCH_SAFE_LIMBS | Get safe_limbs count for radix |
| FETCH_P_LIMB | Get p's limb at index |
| LIMB_P_DIFF_RANGE | Range check limb comparison |

### 6.2 Memory Variant (to_radix_mem.pil)

The memory-aware variant adds:
- Error handling (dst out of range, invalid radix, truncation)
- Memory write integration
- Execution dispatch integration

**Ghost Row Protection**:
```
sel_should_write_mem * (1 - sel) = 0
```
Prevents inactive rows from firing memory writes.

---

## 7. Test Coverage Assessment

### 7.1 Positive Tests
- ToLeBits: 1, p-1, shortest, padded
- ToLeRadix: basic, p-1, one byte, padded
- Interactions with precomputed tables
- Complex multi-call scenarios

### 7.2 Negative Tests
- NegativeOverflowCheck: Tests value = p (modulus)
- NegativeConsistency: Tests selector, radix, value, safe_limbs mutations
- DstOutOfRange, InvalidRadix, InvalidBitwiseRadix, InvalidNumLimbs
- TruncationError
- Ghost row injection attacks

---

## 8. Findings

### No Critical Vulnerabilities Found

The to_radix gadget is **SOUND** and **COMPLETE**.

### INFO-1: Custom Limb Comparison

The gadget implements its own 8-bit comparison logic instead of using the gt gadget. This is intentional and documented:
- Current 8-bit range check is smaller than gt's 16-bit minimum
- Special EQ case trick using multiplication by 256
- Avoids circuit leakage in simulation

### INFO-2: to_radix_mem Ghost Row Protection

The memory variant includes ghost row protection:
```
sel_should_write_mem * (1 - sel) = 0
```
This prevents malicious provers from creating inactive rows that fire memory write permutations.

---

## 9. Conclusion

**Status**: SOUND

The to_radix.pil gadget correctly implements field element decomposition with:
- Proper overflow protection against the field modulus
- Accumulator-based value reconstruction
- Support for padding limbs
- Comprehensive error handling in the memory variant

The constraint system is complete and no soundness vulnerabilities were identified.

---

## Appendix: Constraint Index

| Constraint | Line | Purpose |
|------------|------|---------|
| START_AFTER_LATCH | 52 | Start after end/first_row |
| SELECTOR_ON_START | 56 | sel=1 on start rows |
| SELECTOR_CONSISTENCY | 59 | sel constant within computation |
| LIMB_RANGE | 102 | Range check limb |
| LIMB_LESS_THAN_RADIX_RANGE | 112 | Range check limb < radix |
| FETCH_SAFE_LIMBS | 140 | Lookup safe_limbs |
| FETCH_P_LIMB | 162 | Lookup p's limb |
| LIMB_P_DIFF_RANGE | 201 | Range check comparison |
| OVERFLOW_CHECK | 213 | Require acc_under_p at unsafe limb |
| CONSTANT_CONSISTENCY_RADIX | 219 | Radix constant |
| CONSTANT_CONSISTENCY_VALUE | 222 | Value constant |
| CONSTANT_CONSISTENCY_SAFE_LIMBS | 225 | safe_limbs constant |
