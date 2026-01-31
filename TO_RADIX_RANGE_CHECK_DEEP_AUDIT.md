# Deep Security Audit: to_radix.pil, to_radix_mem.pil, range_check.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL files: `pil/vm2/to_radix.pil` (226 lines), `pil/vm2/to_radix_mem.pil` (290 lines), `pil/vm2/range_check.pil` (230 lines)
- [x] Located dependencies: precomputed.pil, gt.pil, memory.pil
- [x] Located callers: execution.pil (#[DISPATCH_TO_TO_RADIX]), scalar_mul.pil (#[TO_RADIX])

### Phase 2: Understanding
- [x] Documented gadget purposes (radix decomposition, memory I/O, range checking)
- [x] Listed all witnesses
- [x] Listed all constraints
- [x] Understood overflow protection mechanism

### Phase 3: Soundness
- [x] Verified accumulation logic
- [x] Analyzed overflow protection (p-comparison)
- [x] Checked range check limb coverage
- [x] Verified dynamic range check

### Phase 4: Completeness
- [x] Reviewed error handling
- [x] Checked edge cases (zero value, padding limbs)
- [x] Verified truncation detection

### Phase 5: Integration
- [x] Verified execution dispatch (permutation)
- [x] Checked scalar_mul interaction (lookup)
- [x] Verified memory write permutation

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/to_radix.pil` | 226 | Field element decomposition into radix limbs |
| `pil/vm2/to_radix_mem.pil` | 290 | Memory I/O for TORADIXBE opcode |
| `pil/vm2/range_check.pil` | 230 | Generic range check for values up to 128 bits |

---

## 2. Gadget Architecture

### 2.1 to_radix.pil Purpose

Decomposes a field element `value` into limbs in a given radix (base 2-256):

```
value = limb[0] + limb[1]*radix + limb[2]*radix^2 + ... + limb[n]*radix^n
```

**Key Features**:
- Little-endian decomposition (limb[0] is least significant)
- Accumulator tracks running sum
- `found` flag indicates when accumulator equals value
- Overflow protection ensures value < p (field modulus)

### 2.2 to_radix_mem.pil Purpose

Memory interface for TORADIXBE opcode:
- Reads value, radix, num_limbs from execution registers
- Validates inputs (radix in [2,256], address bounds)
- Writes decomposed limbs to memory in **big-endian** order
- Reports truncation error if value doesn't fit in num_limbs

### 2.3 range_check.pil Purpose

Generic range checking for values up to 128 bits:
- Decomposes value into eight 16-bit limbs (u16_r0...u16_r7)
- Selects appropriate check width (is_lte_u16...is_lte_u128)
- Dynamic range check for the most significant limb (u16_r7)

### 2.4 Trace Structure (to_radix)

```
| value | radix | limb | limb_index | acc  | found | is_unsafe | not_padding | start | end |
|-------|-------|------|------------|------|-------|-----------|-------------|-------|-----|
| 1337  |  10   |  7   |      0     |   7  |   0   |     0     |      1      |   1   |  0  |
| 1337  |  10   |  3   |      1     |  37  |   0   |     0     |      1      |   0   |  0  |
| 1337  |  10   |  3   |      2     | 337  |   0   |     0     |      1      |   0   |  0  |
| 1337  |  10   |  1   |      3     |1337  |   1   |     0     |      1      |   0   |  0  |
| 1337  |  10   |  0   |      4     |1337  |   1   |     0     |      1      |   0   |  0  |
...
| 1337  |  10   |  0   |     76     |1337  |   1   |     1     |      1      |   0   |  0  | ← unsafe limb
| 1337  |  10   |  0   |     77     |1337  |   1   |     0     |      0      |   0   |  1  | ← padding
```

---

## 3. to_radix.pil Constraints

### 3.1 Limb Range Check

```pil
// to_radix.pil:101-115
#[LIMB_RANGE]
sel { limb } in precomputed.sel_range_8 { precomputed.clk };

// Limb should be less than radix
pol commit limb_radix_diff;
sel * (radix - 1 - limb - limb_radix_diff) = 0;

#[LIMB_LESS_THAN_RADIX_RANGE]
sel { limb_radix_diff } in precomputed.sel_range_8 { precomputed.clk };
```

**Analysis**:
- `limb` is constrained to [0, 255] via 8-bit range check
- `limb < radix` proven by showing `radix - 1 - limb >= 0` via range check

### 3.2 Accumulation

```pil
// to_radix.pil:118-121
// On start, current acc must be equal to limb
start * (acc - limb) = 0;
// Next acc must be current acc + next_exponent*next_limb
not_end * (acc + exponent' * limb' - acc') = 0;
```

**Analysis**: Accumulator grows as `acc' = acc + exponent' * limb'`, building `value` from limbs.

### 3.3 Found Detection

```pil
// to_radix.pil:123-132
pol REM = value - acc;
pol commit rem_inverse;
sel * (REM * (found * (1 - rem_inverse) + rem_inverse) - 1 + found) = 0;

// when found is 1, next limb is 0
not_end * found * limb' = 0;

// We can only enable end when found is one
(1 - found) * end = 0;
```

**Analysis**: Zero-check pattern - `found = 1` iff `value = acc`. Once found, all subsequent limbs must be 0.

### 3.4 Overflow Protection (Critical)

```pil
// to_radix.pil:137-165
#[FETCH_SAFE_LIMBS]
start { radix, safe_limbs }
in precomputed.sel_to_radix_p_limb_counts { precomputed.clk, precomputed.to_radix_safe_limbs };

// is_unsafe_limb is on when limb_index == safe_limbs
pol safety_diff = limb_index - safe_limbs;
sel * (safety_diff * (is_unsafe_limb * (1 - safety_diff_inverse) + safety_diff_inverse) - 1 + is_unsafe_limb) = 0;

#[FETCH_P_LIMB]
not_padding_limb { radix, limb_index, p_limb }
in precomputed.sel_p_decomposition { ... };
```

**Key Insight**: `safe_limbs` is the number of limbs where no overflow is possible. At `limb_index == safe_limbs`, the `is_unsafe_limb` flag is set.

### 3.5 Accumulator Under P Check

```pil
// to_radix.pil:167-213
// limb comparison with p_limb
pol LIMB_LT_P = p_limb - limb - 1;
pol LIMB_GT_P = limb - p_limb - 1;
pol LIMB_EQ_P = (limb - p_limb) * 256;  // Clever trick!

// Range check validates comparison
#[LIMB_P_DIFF_RANGE]
not_padding_limb { limb_p_diff } in precomputed.sel_range_8 { precomputed.clk };

// Propagate acc_under_p flag
start * (acc_under_p - limb_lt_p) = 0;
not_end * ((acc_under_p - limb_lt_p') * limb_eq_p' + limb_lt_p' - acc_under_p') = 0;

// On unsafe limb, must be under p
#[OVERFLOW_CHECK]
is_unsafe_limb * (1 - acc_under_p) = 0;
```

**Analysis**:
- At each limb, track whether accumulator is definitively < p
- `limb_lt_p`: current limb < p's limb
- `limb_eq_p`: current limb = p's limb (propagate previous status)
- At unsafe limb, `acc_under_p` must be 1, proving value < p

### 3.6 Constant Propagation

```pil
// to_radix.pil:218-225
#[CONSTANT_CONSISTENCY_RADIX]
not_end * (radix - radix') = 0;

#[CONSTANT_CONSISTENCY_VALUE]
not_end * (value - value') = 0;

#[CONSTANT_CONSISTENCY_SAFE_LIMBS]
not_end * (safe_limbs - safe_limbs') = 0;
```

---

## 4. to_radix_mem.pil Constraints

### 4.1 Address Bounds Check

```pil
// to_radix_mem.pil:117-126
pol commit write_addr_upper_bound;
start * (write_addr_upper_bound - dst_addr - num_limbs) = 0;

#[CHECK_DST_ADDR_IN_RANGE]
start { write_addr_upper_bound, max_mem_size, sel_dst_out_of_range_err }
in gt.sel_others { gt.input_a, gt.input_b, gt.res };
```

### 4.2 Radix Validation

```pil
// to_radix_mem.pil:145-157
#[CHECK_RADIX_LT_2]
start { two, radix, sel_radix_lt_2_err }
in gt.sel_others { gt.input_a, gt.input_b, gt.res };

#[CHECK_RADIX_GT_256]
start { radix, two_five_six, sel_radix_gt_256_err }
in gt.sel_others { gt.input_a, gt.input_b, gt.res };

// If is_output_bits = 1, radix must be 2
#[IS_OUTPUT_BITS_IMPLY_RADIX_2]
start * is_output_bits * (1 - sel_invalid_bitwise_radix) * (radix - 2) = 0;
```

### 4.3 Zero-Check for num_limbs and value

```pil
// to_radix_mem.pil:163-176
#[ZERO_CHECK_NUM_LIMBS]
start * (num_limbs * (sel_num_limbs_is_zero * (1 - num_limbs_inv) + num_limbs_inv) - 1 + sel_num_limbs_is_zero) = 0;

#[ZERO_CHECK_VALUE]
start * (value_to_decompose * (sel_value_is_zero * (1 - value_inv) + value_inv) - 1 + sel_value_is_zero) = 0;

// Error if num_limbs = 0 but value != 0
sel_invalid_num_limbs_err = sel_num_limbs_is_zero * (1 - sel_value_is_zero);
```

### 4.4 Error Consolidation

```pil
// to_radix_mem.pil:182-185
pol commit input_validation_error;
input_validation_error = 1 - (1 - sel_dst_out_of_range_err) * (1 - sel_radix_lt_2_err)
    * (1 - sel_radix_gt_256_err) * (1 - sel_invalid_bitwise_radix)
    * (1 - sel_invalid_num_limbs_err);
```

### 4.5 Lookup to to_radix

```pil
// to_radix_mem.pil:205-208
#[INPUT_OUTPUT_TO_RADIX]
sel_should_decompose { value_to_decompose, limb_index_to_lookup, radix, limb_value, value_found }
in to_radix.sel { to_radix.value, to_radix.limb_index, to_radix.radix, to_radix.limb, to_radix.found };
```

**Note**: `limb_index_to_lookup = num_limbs - 1` for big-endian conversion.

### 4.6 Truncation Error

```pil
// to_radix_mem.pil:218-219
#[TRUNCATION_ERROR]
sel_truncation_error = start * sel_should_decompose * (1 - value_found);
```

**Analysis**: If on start row the value hasn't been "found" at the last limb index, it's truncated.

### 4.7 Memory Write (Permutation)

```pil
// to_radix_mem.pil:279-289
#[WRITE_MEM]
sel_should_write_mem {
    execution_clk, space_id,
    dst_addr, limb_value,
    output_tag, sel_should_write_mem
} is memory.sel_to_radix_write { ... };
```

**Uses `is` (permutation)**: Ensures bijective memory writes.

---

## 5. range_check.pil Constraints

### 5.1 Limb Decomposition

```pil
// range_check.pil:71-110
pol commit u16_r0, u16_r1, u16_r2, u16_r3, u16_r4, u16_r5, u16_r6, u16_r7;

pol RESULT = is_lte_u16  * (PX_0 + R7_0) + is_lte_u32  * (PX_1 + R7_1) + ...

#[CHECK_RECOMPOSITION]
sel * (RESULT - value) = 0;
```

**Analysis**: Value decomposed into 16-bit limbs. The `is_lte_uXX` selector determines how many limbs are used.

### 5.2 Dynamic Range Check

```pil
// range_check.pil:166-185
// dyn_rng_chk_bits = rng_chk_bits - (is_lte_u32 * 16) - (is_lte_u48 * 32) - ...
dyn_rng_chk_bits - (rng_chk_bits - ...) = 0;

#[DYN_RNG_CHK_POW_2]
sel { dyn_rng_chk_bits, dyn_rng_chk_pow_2 } in precomputed.sel_range_8 { precomputed.clk, precomputed.power_of_2 };

// u16_r7 < dyn_rng_chk_pow_2
pol commit dyn_diff;
sel * (dyn_diff - (dyn_rng_chk_pow_2 - u16_r7 - 1)) = 0;

#[DYN_DIFF_IS_U16]
sel { dyn_diff } in precomputed.sel_range_16 { precomputed.clk };
```

**Analysis**: The most significant limb (u16_r7) is dynamically range-checked to `dyn_rng_chk_bits` bits.

### 5.3 16-bit Limb Range Checks

```pil
// range_check.pil:214-229
#[R0_IS_U16]
sel_r0_16_bit_rng_lookup { u16_r0 } in precomputed.sel_range_16 { precomputed.clk };
// ... R1 through R6 ...
#[R7_IS_U16]
sel { u16_r7 } in precomputed.sel_range_16 { precomputed.clk };
```

### 5.4 Cumulative Lookup Selectors

```pil
// range_check.pil:197-212
pol CUM_LTE_128 = is_lte_u128;
pol CUM_LTE_112 = is_lte_u112 + CUM_LTE_128;
// ...
sel_r0_16_bit_rng_lookup - CUM_LTE_32 = 0;
sel_r1_16_bit_rng_lookup - CUM_LTE_48 = 0;
// ...
```

**Analysis**: Lookup selectors are cumulative - larger range checks include all smaller limb range checks.

---

## 6. Soundness Verification

### 6.1 Attack Surface Analysis (to_radix.pil)

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Forge limb value | #[LIMB_RANGE] + #[LIMB_LESS_THAN_RADIX_RANGE] | PROTECTED |
| Wrong accumulation | Explicit accumulator constraint | PROTECTED |
| Skip limbs | limb_index increment constraint | PROTECTED |
| Value >= p | #[OVERFLOW_CHECK] at unsafe limb | PROTECTED |
| Forge found flag | Zero-check pattern with inverse | PROTECTED |
| Non-zero padding | `(1 - not_padding_limb) * limb = 0` | PROTECTED |

### 6.2 Attack Surface Analysis (to_radix_mem.pil)

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Out-of-bounds write | #[CHECK_DST_ADDR_IN_RANGE] GT lookup | PROTECTED |
| Invalid radix | #[CHECK_RADIX_LT_2], #[CHECK_RADIX_GT_256] | PROTECTED |
| Forge decomposition | #[INPUT_OUTPUT_TO_RADIX] lookup | PROTECTED |
| Truncation bypass | #[TRUNCATION_ERROR] with value_found | PROTECTED |
| Malicious memory write | #[WRITE_MEM] permutation | PROTECTED |
| Ghost row injection | #[SEL_SHOULD_WRITE_MEM_REQUIRES_SEL] | PROTECTED |

### 6.3 Attack Surface Analysis (range_check.pil)

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Wrong limb decomposition | #[CHECK_RECOMPOSITION] | PROTECTED |
| Skip limb range checks | Cumulative lookup selectors | PROTECTED |
| Forge dyn_rng_chk_bits | #[DYN_RNG_CHK_POW_2] lookup | PROTECTED |
| Overflow u16_r7 | #[DYN_DIFF_IS_U16] proves difference >= 0 | PROTECTED |
| Value > 2^128 | Range check on limbs makes unsatisfiable | PROTECTED |

### 6.4 Critical Security Properties

#### 6.4.1 Overflow Protection in to_radix

The p-comparison mechanism is sound:

1. **safe_limbs lookup**: Gets the index where overflow could first occur
2. **is_unsafe_limb detection**: Zero-check for `limb_index - safe_limbs`
3. **Limb-by-limb comparison**: Tracks `acc_under_p` flag
4. **Final check**: `is_unsafe_limb * (1 - acc_under_p) = 0`

This ensures the decomposed value is canonical (< p).

#### 6.4.2 Range Check Soundness

The range check gadget handles arbitrary bit widths [0, 128]:

1. **Mutual exclusivity**: Exactly one `is_lte_uXX` is active
2. **Recomposition**: Value reconstructed from limbs
3. **Dynamic check**: Top limb range-checked to remaining bits
4. **Underflow detection**: `dyn_diff >= 0` proven via 16-bit range check

Example: Checking 100-bit range
- `is_lte_u112 = 1`, using `u16_r0...u16_r6` and `u16_r7`
- `dyn_rng_chk_bits = 100 - 96 = 4`
- `u16_r7 < 2^4 = 16` verified

#### 6.4.3 Big-Endian Conversion

to_radix is little-endian, but TORADIXBE opcode expects big-endian:

```pil
limb_index_to_lookup = sel_should_decompose * (num_limbs - 1);
```

The start row looks up the **last** limb (most significant), enabling:
1. Truncation detection in start row
2. Decreasing limb_index for big-endian output

---

## 7. Findings

### No Critical Vulnerabilities Found

All three gadgets are **SOUND**.

### INFO-1: Clever EQ Case Handling

```pil
pol LIMB_EQ_P = (limb - p_limb) * 256;
```

Multiplying by 256 means any non-zero difference is > 255, failing the 8-bit range check. Only 0 * 256 = 0 passes.

### INFO-2: Radix Bounds

The gadget supports radix in [2, 256]. For radix = 2 (bits), `is_output_bits` must be set for U1 memory tag.

### INFO-3: Padding Limbs

After `is_unsafe_limb`, all remaining rows are padding with `limb = 0` and `p_limb = 0`. This handles users requesting more limbs than strictly necessary.

### INFO-4: Value > 2^128 in range_check

From comments:
> Any val > 2^128 is not satisfiable (would fail #[CHECK_RECOMPOSITION] combined with the 16-bit range checks)

This is used as an assumption in gt.pil.

### INFO-5: Multiple Lookup Selectors in range_check

```pil
(sel_keccak + sel_gt + sel_memory + sel_alu) * (1 - sel) = 0;
```

Different callers use different selectors for inverse generation decoupling.

---

## 8. Conclusion

**Status**: SOUND

All three gadgets are **correctly implemented** with:

**to_radix.pil**:
- Sound limb decomposition with radix bounds
- Correct accumulation and found detection
- Complete overflow protection via p-comparison
- Proper padding limb handling

**to_radix_mem.pil**:
- Comprehensive error handling (bounds, radix, truncation)
- Correct big-endian conversion via reverse lookup
- Memory write via permutation
- Ghost row injection prevention

**range_check.pil**:
- Flexible range checking up to 128 bits
- Sound limb decomposition with recomposition check
- Dynamic range check for top limb
- Cumulative lookup selectors for efficiency

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

### to_radix.pil

| Constraint | Purpose |
|------------|---------|
| LIMB_RANGE | Limb is 8-bit |
| LIMB_LESS_THAN_RADIX_RANGE | limb < radix |
| (accumulation) | acc' = acc + exponent' * limb' |
| (found detection) | Zero-check for value - acc |
| FETCH_SAFE_LIMBS | Get overflow threshold |
| FETCH_P_LIMB | Get p's limb at index |
| LIMB_P_DIFF_RANGE | Validate limb comparison |
| OVERFLOW_CHECK | acc < p at unsafe limb |
| CONSTANT_CONSISTENCY_* | Propagate inputs |

### to_radix_mem.pil

| Constraint | Purpose |
|------------|---------|
| CHECK_DST_ADDR_IN_RANGE | Address bounds |
| CHECK_RADIX_LT_2 | radix >= 2 |
| CHECK_RADIX_GT_256 | radix <= 256 |
| IS_OUTPUT_BITS_IMPLY_RADIX_2 | bits mode requires radix 2 |
| ZERO_CHECK_NUM_LIMBS | Detect num_limbs = 0 |
| ZERO_CHECK_VALUE | Detect value = 0 |
| INPUT_OUTPUT_TO_RADIX | Lookup decomposition |
| TRUNCATION_ERROR | Detect incomplete decomposition |
| WRITE_MEM | Memory permutation |

### range_check.pil

| Constraint | Purpose |
|------------|---------|
| IS_LTE_MUTUALLY_EXCLUSIVE | One bit-width active |
| CHECK_RECOMPOSITION | value = sum of limbs |
| DYN_RNG_CHK_POW_2 | Get 2^dyn_bits |
| DYN_DIFF_IS_U16 | u16_r7 < 2^dyn_bits |
| R0_IS_U16...R7_IS_U16 | Limb range checks |

## Appendix: Overflow Protection Example

For value = 1337, radix = 10:

```
p ≈ 21888... (254-bit prime)
p in base 10 = 2188...561 (77 digits)
safe_limbs = 76 (first 76 limbs cannot overflow)

Limb 0: 7 vs p[0]=1  → limb > p_limb, acc_under_p = 0
Limb 1: 3 vs p[1]=6  → limb < p_limb, acc_under_p = 1
...
Limb 76 (unsafe): 0 vs p[76]=2 → acc_under_p still 1 → PASS
```

Since `acc_under_p = 1` at the unsafe limb, value is canonical.
