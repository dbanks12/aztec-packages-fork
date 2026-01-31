# Deep Security Audit: range_check.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL file: `pil/vm2/range_check.pil` (230 lines)
- [x] Located simulation code: `simulation/gadgets/range_check.cpp` (16 lines)
- [x] Located trace generation: `tracegen/range_check_trace.cpp` (110 lines)
- [x] Located tests: `range_check.test.cpp`, `range_check_trace.test.cpp`
- [x] Identified callers: 40+ lookups from 8 different gadgets

### Phase 2: Understanding
- [x] Documented gadget purpose
- [x] Listed all witnesses
- [x] Listed all constraints
- [x] Listed all lookups
- [x] Understood data flow

### Phase 3: Soundness
- [x] Verified each constraint
- [x] Analyzed attack vectors
- [x] Checked lookup soundness
- [x] Verified selector constraints

### Phase 4: Completeness
- [x] Reviewed trace generation
- [x] Checked for uninitialized variables
- [x] Verified edge case handling
- [x] Reviewed test coverage

### Phase 5: Integration
- [x] Verified caller usage
- [x] Checked cross-gadget interactions

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/range_check.pil` | 230 | Core range check constraints |
| `simulation/gadgets/range_check.cpp` | 16 | Simulation (trivial - just emits) |
| `tracegen/range_check_trace.cpp` | 110 | Trace generation |
| Tests | 177 | Unit tests for trace generation |

---

## 2. Gadget Architecture

### 2.1 Purpose

The range_check gadget proves that a value fits within a specified bit width:
```
sel { val, num_bits } in range_check.sel_XXX { range_check.value, range_check.rng_chk_bits };
```

Asserts that `val < 2^num_bits` for any `0 <= val < 2^128` and `0 <= num_bits <= 128`.

### 2.2 Limb Decomposition

Values are decomposed into eight 16-bit limbs:
- `u16_r0...u16_r6`: Fixed 16-bit limbs (fully constrained to 16-bit range)
- `u16_r7`: Dynamic limb (MSB) with variable bit width

### 2.3 Bit Size Categories

| is_lte_x | Active Limbs | Dynamic Bits |
|----------|--------------|--------------|
| is_lte_u16 | r7 only | rng_chk_bits |
| is_lte_u32 | r0, r7 | rng_chk_bits - 16 |
| is_lte_u48 | r0-r1, r7 | rng_chk_bits - 32 |
| is_lte_u64 | r0-r2, r7 | rng_chk_bits - 48 |
| is_lte_u80 | r0-r3, r7 | rng_chk_bits - 64 |
| is_lte_u96 | r0-r4, r7 | rng_chk_bits - 80 |
| is_lte_u112 | r0-r5, r7 | rng_chk_bits - 96 |
| is_lte_u128 | r0-r6, r7 | rng_chk_bits - 112 |

---

## 3. Simulation Code Analysis

### 3.1 Trivial Implementation

```cpp
// simulation/gadgets/range_check.cpp:8-13
void RangeCheck::assert_range(uint128_t value, uint8_t num_bits)
{
    BB_ASSERT(num_bits <= 128 && "Range checks aren't supported for bit-sizes > 128");
    events.emit({ .value = value, .num_bits = num_bits });
}
```

**Analysis**: The simulation is trivial - it just emits an event. The actual range checking happens in the PIL constraints. This is correct because:
1. The simulation trusts that values ARE in range (honest prover)
2. The PIL constraints enforce range validity for soundness

---

## 4. Trace Generation Analysis

### 4.1 Limb Decomposition

```cpp
// tracegen/range_check_trace.cpp:37-49
for (size_t i = 0; i < 8; i++) {
    if (num_bits <= 16) {
        dynamic_slice_register = static_cast<uint16_t>(value);
        index_of_most_sig_16b_chunk = i;
        dynamic_bits = num_bits;
        break;
    }
    fixed_slice_registers[i] = static_cast<uint16_t>(value);
    num_bits -= 16;
    value >>= 16;
}
```

**Verified**: Correctly decomposes value into 16-bit chunks with dynamic MSB.

### 4.2 Dynamic Difference Calculation

```cpp
// tracegen/range_check_trace.cpp:51
auto dynamic_diff = static_cast<uint16_t>((1 << dynamic_bits) - dynamic_slice_register - 1);
```

**Verified**: `dyn_diff >= 0` iff `u16_r7 < 2^dyn_rng_chk_bits`.

### 4.3 Cumulative Lookup Selectors

```cpp
// tracegen/range_check_trace.cpp:83-89
{ C::range_check_sel_r0_16_bit_rng_lookup, index_of_most_sig_16b_chunk > 0 ? 1 : 0 },
{ C::range_check_sel_r1_16_bit_rng_lookup, index_of_most_sig_16b_chunk > 1 ? 1 : 0 },
// ...
{ C::range_check_sel_r6_16_bit_rng_lookup, index_of_most_sig_16b_chunk > 6 ? 1 : 0 },
```

**Verified**: Cumulative selectors match PIL constraints (CUM_LTE_* definitions).

---

## 5. PIL Constraint Analysis

### 5.1 Selector Constraints

```pil
// range_check.pil:19-32
sel * (1 - sel) = 0;
sel_keccak * (1 - sel_keccak) = 0;
sel_gt * (1 - sel_gt) = 0;
sel_memory * (1 - sel_memory) = 0;
sel_alu * (1 - sel_alu) = 0;

// If any specialized selector is 1, main selector must be 1
(sel_keccak + sel_gt + sel_memory + sel_alu) * (1 - sel) = 0;
```

**Analysis**: Allows callers to use different selectors for log-derivative batching while ensuring the main `sel` is active.

### 5.2 Mutual Exclusivity

```pil
// range_check.pil:68-69
#[IS_LTE_MUTUALLY_EXCLUSIVE]
is_lte_u16 + is_lte_u32 + is_lte_u48 + is_lte_u64 + is_lte_u80 + is_lte_u96 + is_lte_u112 + is_lte_u128 = sel;
```

**Analysis**: Exactly one is_lte_* flag must be set when `sel = 1`.

### 5.3 Recomposition Check

```pil
// range_check.pil:103-110
pol RESULT = is_lte_u16  * (PX_0 + R7_0) + is_lte_u32  * (PX_1 + R7_1) + ...

#[CHECK_RECOMPOSITION]
sel * (RESULT - value) = 0;
```

**Analysis**: Verifies that the limbs correctly reconstruct the original value.

### 5.4 Dynamic Range Check (Core Soundness)

```pil
// range_check.pil:166-185
// Dynamic bits = rng_chk_bits - (offset based on is_lte_*)
dyn_rng_chk_bits - (rng_chk_bits - (is_lte_u32 * 16) - ... - (is_lte_u128 * 112)) = 0;

// Get power of 2 via lookup
#[DYN_RNG_CHK_POW_2]
sel { dyn_rng_chk_bits, dyn_rng_chk_pow_2 } in precomputed.sel_range_8 { precomputed.clk, precomputed.power_of_2 };

// Compute difference and verify non-negative
sel * (dyn_diff - (dyn_rng_chk_pow_2 - u16_r7 - 1)) = 0;

#[DYN_DIFF_IS_U16]
sel { dyn_diff } in precomputed.sel_range_16 { precomputed.clk };
```

**Analysis**:
1. `dyn_rng_chk_bits` is computed based on which is_lte_* is active
2. `dyn_rng_chk_pow_2 = 2^dyn_rng_chk_bits` via 8-bit lookup (constrains bits to [0,255])
3. `dyn_diff = dyn_rng_chk_pow_2 - u16_r7 - 1` must be in [0, 2^16-1]
4. If `u16_r7 >= 2^dyn_rng_chk_bits`, then `dyn_diff` underflows (fails lookup)

### 5.5 Limb Range Checks

```pil
// range_check.pil:214-229
#[R0_IS_U16]
sel_r0_16_bit_rng_lookup { u16_r0 } in precomputed.sel_range_16 { precomputed.clk };
// ... through R7_IS_U16
#[R7_IS_U16]
sel { u16_r7 } in precomputed.sel_range_16 { precomputed.clk };
```

**Analysis**: All active limbs are constrained to 16-bit range via lookups.

---

## 6. Test Coverage Analysis

### 6.1 Trace Generation Tests

| Test | Description | Coverage |
|------|-------------|----------|
| RangeCheckLte16Bit | 7-bit value | ✓ |
| RangeCheckLte48Bit | 34-bit value | ✓ |
| RangeCheckLte128Bit | 128-bit value | ✓ |

### 6.2 Coverage Gaps

| Test Case | Status |
|-----------|--------|
| Boundary values (e.g., 2^n - 1) | NOT COVERED |
| Zero value | NOT COVERED |
| Maximum 128-bit value | NOT COVERED |
| All is_lte_* categories | PARTIAL (3/8) |

**Recommendation**: Add comprehensive boundary tests.

---

## 7. Caller Analysis (40+ Callers)

### 7.1 By Gadget

| Caller | Selector | Usage |
|--------|----------|-------|
| memory.pil | sel_memory | Memory address bounds |
| keccakf1600.pil | sel_keccak | Rotation bit checks (24 lookups) |
| gt.pil | sel_gt | Difference range check |
| alu.pil | sel_alu | Decomposition checks (6 lookups) |
| update_check.pil | sel | Tree position checks |
| ff_gt.pil | sel | Field element comparison |
| instr_fetching.pil | sel | PC bounds check |

### 7.2 Lookup Pattern

All callers use the pattern:
```pil
sel { value, num_bits } in range_check.sel_XXX { range_check.value, range_check.rng_chk_bits };
```

**Uses `in` (lookup)**: Correct - many callers may need the same range check.

---

## 8. Soundness Verification

### 8.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Value > 2^128 | Limb lookups prevent | PROTECTED |
| Wrong is_lte_* choice (higher) | DYN_DIFF underflows | PROTECTED |
| Wrong is_lte_* choice (lower) | dyn_rng_chk_bits > 16 causes DYN_DIFF overflow | PROTECTED |
| Forged limbs | Limb lookups + CHECK_RECOMPOSITION | PROTECTED |
| Negative dyn_rng_chk_bits | 8-bit lookup fails | PROTECTED |

### 8.2 Counter-Examples (from PIL comments)

**Valid Proof (value=3, rng_chk_bits=100):**
1. is_lte_u112 = 1
2. u16_r0 = 3, all others = 0
3. dyn_rng_chk_bits = 100 - 96 = 4
4. dyn_rng_chk_pow_2 = 16
5. dyn_diff = 16 - 0 - 1 = 15 (passes U16 check)

**Invalid Proof (claiming wrong is_lte):**
1. value = 3, rng_chk_bits = 100, is_lte_u16 = 1 (wrong!)
2. u16_r7 = 3 (passes recomposition)
3. dyn_rng_chk_bits = 100 (not reduced)
4. dyn_rng_chk_pow_2 = 2^100 (huge)
5. dyn_diff = 2^100 - 3 - 1 (fails U16 lookup!)

**Invalid Proof (negative dynamic bits):**
1. value = 3, rng_chk_bits = 100, is_lte_u128 = 1 (wrong!)
2. dyn_rng_chk_bits = 100 - 112 = -12 (negative!)
3. Fails DYN_RNG_CHK_POW_2 lookup (clk cannot be -12)

---

## 9. Findings

### No Critical Vulnerabilities Found

The range_check gadget is **SOUND**.

### INFO-1: Fundamental Primitive

This gadget is used by 40+ lookups across 8 different gadgets. Any bug here would have system-wide impact.

### INFO-2: Values > 2^128 Unsatisfiable

As noted in the PIL comments:
> Any val > 2^128 is not satisfiable (would fail #[CHECK_RECOMPOSITION] combined with the 16-bit range checks on the limbs).

This property is used as an assumption in gt.pil.

### INFO-3: Multiple Selectors for Log-Derivative Batching

The sel_keccak, sel_gt, sel_memory, sel_alu selectors exist to decouple inverse generation for log-derivative lookups, improving efficiency.

---

## 10. Conclusion

**Status**: SOUND

The range_check gadget is **correctly implemented** with:
- Proper limb decomposition with recomposition verification
- Dynamic range check on MSB limb
- Cumulative lookup selectors for active limbs
- Sound constraint structure that prevents all analyzed attacks
- Comprehensive caller base (fundamental primitive)

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

| Constraint | Purpose |
|------------|---------|
| IS_LTE_MUTUALLY_EXCLUSIVE | Exactly one bit size selected |
| CHECK_RECOMPOSITION | Limbs reconstruct value |
| DYN_RNG_CHK_POW_2 | Get 2^dyn_bits via lookup |
| DYN_DIFF_IS_U16 | Verify u16_r7 < 2^dyn_bits |
| R0_IS_U16 ... R7_IS_U16 | Limb range checks |

## Appendix: Recomposition Formula

```
For is_lte_u48:
  RESULT = u16_r0 + u16_r1 * 2^16 + u16_r7 * 2^32

For is_lte_u128:
  RESULT = u16_r0 + u16_r1 * 2^16 + u16_r2 * 2^32 + u16_r3 * 2^48
         + u16_r4 * 2^64 + u16_r5 * 2^80 + u16_r6 * 2^96 + u16_r7 * 2^112
```
