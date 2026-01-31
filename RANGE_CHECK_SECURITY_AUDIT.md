# Range Check PIL Gadget Security Audit

## Executive Summary

This audit examines the range check gadget in the AVM2 (Aztec Virtual Machine 2) implementation. The gadget is responsible for proving that a value `v` fits within `n` bits, i.e., `v < 2^n` for `0 <= n <= 128`.

**Overall Assessment: The gadget is SOUND with minor code quality issues.**

The PIL constraints are well-designed and correctly enforce the range check property. The trace generation correctly implements the constraint-satisfying witness. No critical vulnerabilities were found.

---

## Architecture Overview

### Files Analyzed

| Component | File |
|-----------|------|
| PIL Constraints | `barretenberg/cpp/pil/vm2/range_check.pil` |
| Simulation Gadget | `barretenberg/cpp/src/barretenberg/vm2/simulation/gadgets/range_check.cpp` |
| Trace Generation | `barretenberg/cpp/src/barretenberg/vm2/tracegen/range_check_trace.cpp` |
| Event Definition | `barretenberg/cpp/src/barretenberg/vm2/simulation/events/range_check_event.hpp` |
| Generated Relations | `barretenberg/cpp/src/barretenberg/vm2/generated/relations/range_check.hpp` |
| Lookup Relations | `barretenberg/cpp/src/barretenberg/vm2/generated/relations/lookups_range_check.hpp` |

### How It Works

1. **Decomposition**: The 128-bit value is decomposed into eight 16-bit "slices" (`u16_r0` through `u16_r7`).

2. **Selector Flags**: One of eight mutually exclusive `is_lte_uXX` flags indicates the bit-width boundary (u16, u32, u48, u64, u80, u96, u112, u128).

3. **Recomposition Check**: The constraint `#[CHECK_RECOMPOSITION]` verifies that the slices reconstruct to the original value.

4. **Dynamic Range Check**: The most significant slice (`u16_r7`) undergoes a dynamic range check to handle non-multiple-of-16 bit widths. This uses:
   - `dyn_rng_chk_bits = rng_chk_bits - (base offset based on is_lte_uXX)`
   - `dyn_rng_chk_pow_2 = 2^dyn_rng_chk_bits` (via lookup)
   - `dyn_diff = dyn_rng_chk_pow_2 - u16_r7 - 1` (must be in [0, 2^16))

5. **16-bit Lookups**: Each active slice register has a lookup into the precomputed 16-bit range table.

---

## Soundness Analysis

### Constraint Verification

#### 1. Mutual Exclusivity (`#[IS_LTE_MUTUALLY_EXCLUSIVE]`)
```
is_lte_u16 + is_lte_u32 + ... + is_lte_u128 = sel
```
**Status: SOUND** - Exactly one flag is set when `sel=1`.

#### 2. Recomposition (`#[CHECK_RECOMPOSITION]`)
```
sel * (RESULT - value) = 0
```
Where `RESULT` is computed from slices based on the active `is_lte_uXX` flag.

**Status: SOUND** - Value must equal the sum of weighted slices.

#### 3. Dynamic Bits Calculation (Line 168)
```
dyn_rng_chk_bits - (rng_chk_bits - is_lte_u32*16 - is_lte_u48*32 - ... - is_lte_u128*112) = 0
```
**Status: SOUND** - Correctly computes the residual bits for dynamic checking.

#### 4. Power-of-2 Lookup (`#[DYN_RNG_CHK_POW_2]`)
```
sel { dyn_rng_chk_bits, dyn_rng_chk_pow_2 } in precomputed.sel_range_8 { precomputed.clk, precomputed.power_of_2 }
```
**Status: SOUND** - Ensures `dyn_rng_chk_pow_2 = 2^dyn_rng_chk_bits` for bits in [0, 255].

#### 5. Dynamic Diff Check (`#[DYN_DIFF_IS_U16]`)
```
sel * (dyn_diff - (dyn_rng_chk_pow_2 - u16_r7 - 1)) = 0
sel { dyn_diff } in precomputed.sel_range_16 { precomputed.clk }
```
**Status: SOUND** - Enforces `u16_r7 < 2^dyn_rng_chk_bits` by requiring `dyn_diff` to be a valid 16-bit value.

#### 6. 16-bit Slice Lookups (`#[R0_IS_U16]` through `#[R7_IS_U16]`)
**Status: SOUND** - All active slices are range-checked to [0, 65535].

### Attack Vector Analysis

#### Attack 1: Claiming smaller range with larger value
**Scenario**: Prover claims `value=100` fits in 2 bits (`num_bits=2`).
**Result**: BLOCKED - The `dyn_rng_chk_pow_2 = 4`, `u16_r7 = 100`, so `dyn_diff = 4 - 100 - 1 = -97`. In the field, this is ~`p - 97`, which fails the 16-bit lookup.

#### Attack 2: Using wrong `is_lte_uXX` flag
**Scenario**: For `num_bits=100`, prover sets `is_lte_u16=1` instead of `is_lte_u112=1`.
**Result**: BLOCKED - `dyn_rng_chk_bits = 100 - 0 = 100`, so `dyn_rng_chk_pow_2 = 2^100`. Then `dyn_diff = 2^100 - u16_r7 - 1` would be astronomically large, failing the 16-bit lookup.

#### Attack 3: Negative `dyn_rng_chk_bits`
**Scenario**: Set `is_lte_u128=1` with `num_bits=50` (gives `dyn_rng_chk_bits = 50 - 112 = -62`).
**Result**: BLOCKED - In the field, `-62` wraps to `p - 62`, which fails the power-of-2 lookup (only valid for [0, 255]).

#### Attack 4: Value > 2^128
**Scenario**: Prover attempts to prove a value larger than 2^128.
**Result**: BLOCKED - Maximum representable value with eight 16-bit slices is `2^128 - 1`. Any larger value cannot satisfy `#[CHECK_RECOMPOSITION]` with valid slice values.

---

## Completeness Analysis

### Trace Generation Correctness

The trace generation in `range_check_trace.cpp` correctly:
1. Splits values into 16-bit chunks
2. Sets the appropriate `is_lte_uXX` flag
3. Computes `dyn_rng_chk_bits`, `dyn_rng_chk_pow_2`, and `dyn_diff`
4. Sets lookup selectors based on which slices are active

### Edge Cases Verified

| Test Case | num_bits | value | Status |
|-----------|----------|-------|--------|
| Zero bits | 0 | 0 | PASS (tested in constraint tests) |
| One bit | 1 | 0,1 | PASS |
| Exact boundary | 16 | 65535 | PASS |
| Just over 16 | 17 | 65536 | PASS |
| Maximum | 128 | 2^128-1 | PASS |
| Empty value | Any | 0 | PASS |

---

## Findings

### LOW-1: Uninitialized Array in Trace Generation

**Location**: `range_check_trace.cpp:31`
```cpp
std::array<uint16_t, 7> fixed_slice_registers; // NOT INITIALIZED
```

**Description**: The `fixed_slice_registers` array is not initialized. If the loop exits early (e.g., for `num_bits <= 16`), unused elements contain indeterminate values from the stack.

**Impact**: LOW - The uninitialized values are written to the trace but:
1. They are not constrained (lookup selectors are 0 for unused registers)
2. They don't affect `#[CHECK_RECOMPOSITION]` (only active slices contribute)
3. However, this is undefined behavior in C++ and could theoretically cause issues with sanitizers or in edge cases.

**Recommendation**: Initialize the array:
```cpp
std::array<uint16_t, 7> fixed_slice_registers = {};
```

### INFO-1: Fuzzer Does Not Test num_bits=0

**Location**: `range_check.fuzzer.cpp:64`
```cpp
uint8_t num_bits = fuzzed_data.ConsumeIntegralInRange<uint8_t>(1, 128);
```

**Description**: The fuzzer tests `num_bits` in range [1, 128], never testing `num_bits=0`.

**Impact**: INFO - The edge case `num_bits=0` is tested in unit tests (`range_check.test.cpp:172`), so coverage exists. However, fuzzing this case could find additional bugs.

**Recommendation**: Change to:
```cpp
uint8_t num_bits = fuzzed_data.ConsumeIntegralInRange<uint8_t>(0, 128);
```

### INFO-2: Multiple of 16 Bits Allows Two Valid Witnesses

**Location**: `range_check.pil:47-48` (documented behavior)

**Description**: When `rng_chk_bits` is a multiple of 16, the prover can choose either the exact boundary flag or the next higher one. For example, for `num_bits=16`:
- Valid: `is_lte_u16=1, dyn_rng_chk_bits=16, u16_r7=value`
- Also valid: `is_lte_u32=1, dyn_rng_chk_bits=0, u16_r0=value, u16_r7=0`

**Impact**: INFO - This is documented and does not affect soundness. Both witnesses correctly prove `value < 2^16`. The canonical trace generation always chooses the tighter option.

### INFO-3: Simulation Does Not Validate Input Range

**Location**: `range_check.cpp:8-12`
```cpp
void RangeCheck::assert_range(uint128_t value, uint8_t num_bits)
{
    BB_ASSERT(num_bits <= 128 && "Range checks aren't supported for bit-sizes > 128");
    events.emit({ .value = value, .num_bits = num_bits });
}
```

**Description**: The simulation does not check that `value < 2^num_bits`. It trusts callers to provide valid inputs.

**Impact**: INFO - This is by design. The simulation emits events; constraint checking happens later. Invalid events result in unsatisfiable constraints, correctly failing verification.

---

## Usage Analysis

The range check gadget is used correctly by all dependent modules:

### Memory (`memory.cpp:59`)
```cpp
range_check.assert_range(value_as_uint128, tag_bits);
```
Validates that memory values fit their declared tag sizes.

### ALU (`alu.cpp`)
Used for:
- MUL overflow detection (64-bit limb range checks)
- DIV decomposition validation
- SHL/SHR bit decomposition
- TRUNCATE mid-value range checking

### GT (`gt.cpp:23`)
```cpp
range_check.assert_range(abs_diff, num_bits_bound_16);
```
Validates absolute differences in comparisons. Always uses multiples of 16 for efficiency.

### Field GT (`field_gt.cpp`)
Uses 128-bit range checks for canonical decomposition of field elements.

### Keccak (`keccakf1600.cpp:174-177`)
Range checks rotation witnesses with carefully computed bit widths.

---

## Conclusion

The range check PIL gadget is **correctly implemented and sound**. The constraints properly enforce that a value fits within the specified number of bits. The trace generation correctly produces satisfying witnesses.

**Recommendations**:
1. Fix LOW-1 by initializing `fixed_slice_registers`
2. Consider expanding fuzzer coverage to include `num_bits=0`

No vulnerabilities that would allow a malicious prover to create invalid proofs were found. No completeness issues that would prevent an honest prover from generating valid proofs were found.

---

## Appendix: Constraint Summary

| Constraint | Purpose |
|------------|---------|
| `#[IS_LTE_MUTUALLY_EXCLUSIVE]` | Exactly one `is_lte_uXX` flag |
| `#[CHECK_RECOMPOSITION]` | Value = sum of weighted slices |
| `#[DYN_RNG_CHK_POW_2]` | Lookup `2^dyn_bits` from precomputed table |
| `#[DYN_DIFF_IS_U16]` | Dynamic slice < 2^dyn_bits |
| `#[R0_IS_U16]` - `#[R7_IS_U16]` | 16-bit range for each slice |
| Selector booleans | All selectors ∈ {0, 1} |
| Selector implications | Sub-selectors imply main selector |
