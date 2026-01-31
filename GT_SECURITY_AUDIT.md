# GT (Greater Than) PIL Gadget Security Audit

## Executive Summary

This audit examines the GT (greater-than) gadget in the AVM2 implementation. The gadget proves that for two 128-bit integers `a` and `b`, the result `res = (a > b)` is correct.

**Overall Assessment: The gadget is SOUND and COMPLETE.**

The PIL constraints correctly enforce the greater-than comparison. The trace generation produces valid witnesses. All callers satisfy the required preconditions.

---

## Architecture Overview

### Files Analyzed

| Component | File |
|-----------|------|
| PIL Constraints | `barretenberg/cpp/pil/vm2/gt.pil` |
| Simulation Gadget | `barretenberg/cpp/src/barretenberg/vm2/simulation/gadgets/gt.cpp` |
| Trace Generation | `barretenberg/cpp/src/barretenberg/vm2/tracegen/gt_trace.cpp` |
| Event Definition | `barretenberg/cpp/src/barretenberg/vm2/simulation/events/gt_event.hpp` |
| Generated Relations | `barretenberg/cpp/src/barretenberg/vm2/generated/relations/gt_impl.hpp` |
| Lookup Relations | `barretenberg/cpp/src/barretenberg/vm2/generated/relations/lookups_gt.hpp` |
| Tests | `simulation/gadgets/gt.test.cpp`, `constraining/relations/gt.test.cpp` |
| Fuzzer | `avm_fuzzer/harness/gt.fuzzer.cpp` |

### How It Works

**Inputs:**
- `input_a`: First operand (128-bit integer)
- `input_b`: Second operand (128-bit integer)
- `res`: Boolean result (1 if a > b, 0 otherwise)

**Key Polynomials:**
```
A_LTE_B = input_b - input_a    // Positive when a <= b
A_GT_B = input_a - input_b - 1 // Positive when a > b
abs_diff = A_GT_B if res=1 else A_LTE_B
```

**Main Constraint** (`#[GT_RESULT]`):
```
sel * ( (A_GT_B - A_LTE_B) * res + A_LTE_B - abs_diff ) = 0
```

This simplifies to:
- When `res = 1`: `abs_diff = A_GT_B = a - b - 1`
- When `res = 0`: `abs_diff = A_LTE_B = b - a`

**Range Check Lookup** (`#[GT_RANGE]`):
```
sel { abs_diff, num_bits } in range_check.sel_gt { range_check.value, range_check.rng_chk_bits }
```

Ensures `abs_diff < 2^128`, which proves the correctness of `res`.

### Preconditions

From `gt.pil` lines 4-7:
> Both inputs (input_a and input_b) must be bounded by p - 1 - 2^128
> and the absolute difference between them must be less than 2^128.

These preconditions are satisfied when inputs are 128-bit integers.

---

## Soundness Analysis

### Constraint Verification

#### 1. Result Boolean (`res * (1 - res) = 0`)
**Status: SOUND** - `res` can only be 0 or 1.

#### 2. GT Result Constraint
**Status: SOUND** - The constraint forces `abs_diff` to be computed correctly based on `res`.

#### 3. Range Check Lookup
**Status: SOUND** - Forces `abs_diff < 2^128`, which is only possible when `res` is correct.

### Attack Vector Analysis

#### Attack 1: Claiming a > b when a <= b
**Scenario**: Set `res = 1` when actually `a <= b`.
- `abs_diff = a - b - 1` would be negative
- In the field: `p - (b - a + 1) >> 2^128`
- Range check FAILS ✓

#### Attack 2: Claiming a <= b when a > b
**Scenario**: Set `res = 0` when actually `a > b`.
- `abs_diff = b - a` would be negative
- In the field: `p - (a - b) >> 2^128`
- Range check FAILS ✓

#### Attack 3: Equal values (a = b)
**Correct result**: `res = 0` (a is NOT greater than b)
- `abs_diff = b - a = 0`
- Range check: `0 < 2^16` PASSES ✓

#### Attack 4: Minimal difference (a = b + 1)
**Correct result**: `res = 1`
- `abs_diff = a - b - 1 = 0`
- Range check: `0 < 2^16` PASSES ✓

---

## Completeness Analysis

### Trace Generation Review

**Location**: `gt_trace.cpp:20-23`
```cpp
FF abs_diff = event.result ? a_ff - b_ff - 1 : b_ff - a_ff;
const uint8_t num_bits_bound = static_cast<uint8_t>(static_cast<uint256_t>(abs_diff).get_msb() + 1);
const uint8_t num_bits_bound_16 = static_cast<uint8_t>(((num_bits_bound - 1) / 16 + 1) * 16);
```

**Analysis:**
- Correctly computes `abs_diff` based on the comparison result
- Rounds `num_bits` up to the nearest multiple of 16 for range check optimization
- For `abs_diff = 0`: `get_msb()` returns 0, so `num_bits_bound = 1`, `num_bits_bound_16 = 16` ✓

### Edge Cases Verified

| Test Case | a | b | Expected res | abs_diff | Status |
|-----------|---|---|--------------|----------|--------|
| Equal | 0 | 0 | 0 | 0 | PASS |
| Minimal GT | 2 | 1 | 1 | 0 | PASS |
| Minimal LT | 1 | 2 | 0 | 1 | PASS |
| Max value GT | 2^128-1 | 1 | 1 | 2^128-3 | PASS |
| Max value LT | 2 | 2^128-1 | 0 | 2^128-3 | PASS |

---

## Integration Analysis

### Callers and Precondition Satisfaction

| Caller | Selector | Input Types | Precondition Met? |
|--------|----------|-------------|-------------------|
| alu.pil | sel_alu | Memory values (≤128 bits) | ✓ |
| addressing.pil | sel_addressing | Addresses (32 bits) | ✓ |
| gas.pil | sel_gas | Gas values (bounded) | ✓ |
| data_copy.pil | sel_others | Sizes/offsets | ✓ |
| execution.pil | sel_others | Radix values | ✓ |
| bytecode/update_check.pil | sel_others | Timestamps | ✓ |

All callers use values that are well within the 128-bit bounds required by the preconditions.

---

## Findings

### No Critical or High Findings

The GT gadget is correctly implemented with no soundness or completeness vulnerabilities.

### INFO-1: Undocumented num_bits Flexibility

**Location**: `gt.pil:57-58`
> num_bits is not constrained here but range_check forces that abs_diff < 2^128 no matter what.

**Description**: The `num_bits` witness is not directly constrained. The prover can choose any value ≤ 128. The range_check gadget ensures soundness regardless of the chosen `num_bits`.

**Impact**: INFO - This is by design for performance optimization. Using a smaller `num_bits` reduces the number of 16-bit lookups in the range_check gadget.

### INFO-2: Preconditions Not Enforced in PIL

**Location**: `gt.pil:4-7`

**Description**: The preconditions (inputs bounded by `p - 1 - 2^128`) are documented but not enforced in the PIL. Callers must ensure compliance.

**Impact**: INFO - All current callers satisfy the preconditions. The memory system ensures values are bounded by their tag types (max 128 bits).

---

## Conclusion

The GT PIL gadget is **correctly implemented and secure**. The constraints properly enforce the greater-than comparison for 128-bit integers. The trace generation correctly produces satisfying witnesses. All callers satisfy the documented preconditions.

**No recommendations for code changes.** The implementation is sound.

---

## Appendix: Constraint Summary

| Constraint | Purpose |
|------------|---------|
| `sel * (1 - sel) = 0` | Main selector is boolean |
| `res * (1 - res) = 0` | Result is boolean |
| `#[GT_RESULT]` | abs_diff computed correctly based on res |
| `#[GT_RANGE]` | abs_diff < 2^128 via range_check lookup |
| Selector sum constraint | Sub-selectors imply main selector |
| Sub-selector booleans | All sub-selectors ∈ {0, 1} |

## Appendix: Soundness Proof Sketch

**Claim**: If the constraints are satisfied and `abs_diff < 2^128`, then `res = (input_a > input_b)`.

**Proof**:

Case 1: `res = 1`
- Constraint implies `abs_diff = input_a - input_b - 1`
- For `abs_diff < 2^128` to hold, `input_a - input_b - 1` must be non-negative in the integers
- This means `input_a - input_b >= 1`, i.e., `input_a > input_b` ✓

Case 2: `res = 0`
- Constraint implies `abs_diff = input_b - input_a`
- For `abs_diff < 2^128` to hold, `input_b - input_a` must be non-negative
- This means `input_b >= input_a`, i.e., `input_a <= input_b` (not greater than) ✓

QED.
