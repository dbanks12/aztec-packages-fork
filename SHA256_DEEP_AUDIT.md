# Deep Security Audit: sha256.pil & sha256_mem.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL files: `pil/vm2/sha256.pil` (~600 lines), `pil/vm2/sha256_mem.pil` (~460 lines)
- [x] Located dependencies: bitwise.pil, gt.pil, precomputed.pil, memory.pil
- [x] Located callers: execution.pil (DISPATCH_TO_SHA256_COMPRESSION)

### Phase 2: Understanding
- [x] Documented gadget purposes (compression, memory I/O)
- [x] Listed all witnesses (state, w values, intermediates)
- [x] Listed all constraints (w computation, S0, S1, ch, maj)
- [x] Understood 65-row structure (64 rounds + output)

### Phase 3: Soundness
- [x] Verified bitwise lookups
- [x] Analyzed rotation constraints
- [x] Checked modular addition verification
- [x] Verified error handling completeness

### Phase 4: Completeness
- [x] Reviewed trace shape constraints
- [x] Checked tag error propagation
- [x] Verified round counting

### Phase 5: Integration
- [x] Verified execution dispatch
- [x] Checked sha256_mem memory operations
- [x] Verified bitwise accounting

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/sha256.pil` | ~600 | SHA256 compression function (64 rounds) |
| `pil/vm2/sha256_mem.pil` | ~460 | Memory I/O for state, input, output |

---

## 2. Gadget Architecture

### 2.1 sha256.pil Purpose

Implements the SHA256 compression function:
- **State**: 8 × 32-bit words (a, b, c, d, e, f, g, h)
- **Input**: 16 × 32-bit words (message block)
- **Rounds**: 64 compression rounds
- **Output**: 8 × 32-bit words (updated hash state)

### 2.2 Trace Structure

```
| row | start | latch | rounds_remaining | sel_is_input_round | operation |
|-----|-------|-------|------------------|-------------------|-----------|
|  1  |   1   |   0   |        64        |         1         | Read state + input[0] |
|  2  |   0   |   0   |        63        |         1         | Round 1 + input[1] |
| ... |  ...  |  ...  |        ...       |        ...        | ... |
| 16  |   0   |   0   |        49        |         1         | Round 15 + input[15] |
| 17  |   0   |   0   |        48        |         0         | Round 16 (compute w) |
| ... |  ...  |  ...  |        ...       |        ...        | ... |
| 65  |   0   |   1   |         0        |         0         | Output row |
```

### 2.3 sha256_mem.pil Purpose

Virtual namespace within sha256.pil handling:
- Read 8 state values (horizontal, row 1)
- Read 16 input values (vertical, rows 1-16)
- Write 8 output values (horizontal, row 65)

### 2.4 Data Flow

```
execution.pil (DISPATCH_TO_SHA256_COMPRESSION)
    ↓ permutation (is)
sha256.start
    ↓ permutation (is) to memory (8 state reads, row 1)
    ↓ permutation (is) to memory (16 input reads, rows 1-16)
    ↓ permutation (is) to memory (8 output writes, row 65)
```

---

## 3. Message Schedule (W) Computation

### 3.1 First 16 Rounds

```pil
// sha256.pil:163-168
pol commit sel_is_input_round;
sel_is_input_round = perform_round * (1 - sel_is_input_round);
sel_compute_w = perform_round * (1 - sel_is_input_round);
```

W[0..15] loaded from input memory.

### 3.2 Rounds 16-63 (W Expansion)

```pil
// sha256.pil:130-173
// s0 := (w[i-15] rotr 7) xor (w[i-15] rotr 18) xor (w[i-15] >> 3)
// s1 := (w[i-2] rotr 17) xor (w[i-2] rotr 19) xor (w[i-2] >> 10)
// w[i] := w[i-16] + s0 + w[i-7] + s1

pol COMPUTED_W = helper_w0 + w_s_0 + helper_w9 + w_s_1;
sel_compute_w * ((computed_w_lhs * 2**32 + computed_w_rhs) - COMPUTED_W) = 0;
sel_compute_w * (w - computed_w_rhs) = 0;
```

### 3.3 Rotation Verification

```pil
// sha256.pil:186-198 (example: rotr 7)
sel_compute_w * (helper_w1 - (lhs_w_7 * 2**7 + rhs_w_7)) = 0;
sel_compute_w * (w_15_rotr_7 - (rhs_w_7 * 2**25 + lhs_w_7)) = 0;

#[RANGE_RHS_W_7]
sel_compute_w { two_pow_7, rhs_w_7, sel_compute_w }
in gt.sel_sha256 { gt.input_a, gt.input_b, gt.res };
```

---

## 4. Compression Function

### 4.1 S1 Computation

```pil
// sha256.pil:298-353
// S1 = (e rotr 6) xor (e rotr 11) xor (e rotr 25)

#[S_1_XOR_0]
perform_round { e_rotr_6, e_rotr_11, e_rotr_6_xor_e_rotr_11, xor_sel, u32_tag }
in bitwise.start_sha256 { ... };

#[S_1_XOR_1]
perform_round { e_rotr_6_xor_e_rotr_11, e_rotr_25, s_1, xor_sel, u32_tag }
in bitwise.start_sha256 { ... };
```

### 4.2 Ch Computation

```pil
// sha256.pil:355-377
// ch = (e and f) xor ((not e) and g)

perform_round * (e + not_e - (2**32 - 1)) = 0;

#[CH_AND_0]
perform_round { e, f, e_and_f, and_sel, u32_tag } in bitwise.start_sha256 { ... };

#[CH_AND_1]
perform_round { not_e, g, not_e_and_g, and_sel, u32_tag } in bitwise.start_sha256 { ... };

#[CH_XOR]
perform_round { e_and_f, not_e_and_g, ch, xor_sel, u32_tag } in bitwise.start_sha256 { ... };
```

### 4.3 Maj Computation

```pil
// sha256.pil:438-467
// maj = (a and b) xor (a and c) xor (b and c)

#[MAJ_AND_0]
perform_round { a, b, a_and_b, and_sel, u32_tag } in bitwise.start_sha256 { ... };

#[MAJ_AND_1]
perform_round { a, c, a_and_c, and_sel, u32_tag } in bitwise.start_sha256 { ... };

#[MAJ_AND_2]
perform_round { b, c, b_and_c, and_sel, u32_tag } in bitwise.start_sha256 { ... };

#[MAJ_XOR_0]
perform_round { a_and_b, a_and_c, ab_xor_ac, xor_sel, u32_tag } in bitwise.start_sha256 { ... };

#[MAJ_XOR_1]
perform_round { ab_xor_ac, b_and_c, maj, xor_sel, u32_tag } in bitwise.start_sha256 { ... };
```

### 4.4 State Update

```pil
// sha256.pil:509-516
perform_round * (a' - next_a_rhs) = 0;
perform_round * (b' - a) = 0;
perform_round * (c' - b) = 0;
perform_round * (d' - c) = 0;
perform_round * (e' - next_e_rhs) = 0;
perform_round * (f' - e) = 0;
perform_round * (g' - f) = 0;
perform_round * (h' - g) = 0;
```

### 4.5 Final Output

```pil
// sha256.pil:519-534
pol OUT_A = a + init_a;
last * (OUT_A - (output_a_lhs * 2**32 + output_a_rhs)) = 0;
// ... similar for B through H
```

---

## 5. Memory Operations (sha256_mem.pil)

### 5.1 State/Output Memory (Permutation)

```pil
// sha256_mem.pil:247-341
// 8 permutations for state read OR output write
sel_mem_state_or_output = STATE_READ_CONDITION + OUTPUT_WRITE_CONDITION;

#[MEM_OP_0]
sel_mem_state_or_output { execution_clk, space_id, memory_address[0], memory_register[0], memory_tag[0], rw }
is memory.sel_sha256_op[0] { ... };
// ... 7 more
```

**Critical**: Uses permutation (`is`) for all memory operations.

### 5.2 Input Memory (Permutation)

```pil
// sha256_mem.pil:411-421
sel_read_input_from_memory = sel * (1 - mem_out_of_range_err) * sel_is_input_round * (1 - sel_invalid_state_tag_err);

#[MEM_INPUT_READ]
sel_read_input_from_memory { execution_clk, space_id, input_addr, input, input_tag, precomputed.zero }
is memory.sel_sha256_read { ... };
```

---

## 6. Error Handling

### 6.1 Bounds Checking

```pil
// sha256_mem.pil:151-182
#[CHECK_STATE_ADDR_IN_RANGE]
start { max_state_addr, max_mem_addr, sel_state_out_of_range_err }
in gt.sel_others { ... };

#[CHECK_INPUT_ADDR_IN_RANGE]
start { max_input_addr, max_mem_addr, sel_input_out_of_range_err }
in gt.sel_others { ... };

#[CHECK_OUTPUT_ADDR_IN_RANGE]
start { max_output_addr, max_mem_addr, sel_output_out_of_range_err }
in gt.sel_others { ... };
```

### 6.2 State Tag Validation (Batched)

```pil
// sha256_mem.pil:349-365
pol BATCHED_TAG_CHECK = 2**0 * STATE_TAG_DIFF_0 + 2**3 * STATE_TAG_DIFF_1
                      + 2**6 * STATE_TAG_DIFF_2 + 2**9 * STATE_TAG_DIFF_3
                      + 2**12 * STATE_TAG_DIFF_4 + 2**15 * STATE_TAG_DIFF_5
                      + 2**18 * STATE_TAG_DIFF_6 + 2**21 * STATE_TAG_DIFF_7;

#[BATCH_ZERO_CHECK_READ]
(STATE_READ_CONDITION * BATCHED_TAG_CHECK) * (...) - sel_invalid_state_tag_err = 0;
```

### 6.3 Input Tag Propagation

```pil
// sha256_mem.pil:437-453
#[INPUT_TAG_DIFF_CHECK]
INPUT_TAG_DIFF * (...) - sel_invalid_input_row_tag_err = 0;

#[TAG_ERROR_INIT]
LATCH_CONDITION * (sel_invalid_input_tag_err - sel_invalid_input_row_tag_err) = 0;

#[TAG_ERROR_PROPAGATION]
(1 - LATCH_CONDITION) * (sel_invalid_input_tag_err - sel_invalid_input_tag_err') = 0;
```

### 6.4 Consolidated Error

```pil
// sha256_mem.pil:457-458
err = 1 - (1 - mem_out_of_range_err) * (1 - sel_invalid_state_tag_err) * (1 - sel_invalid_input_tag_err);
```

---

## 7. Soundness Verification

### 7.1 Attack Surface Analysis (sha256.pil)

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Wrong rotation | GT lookup for limb range | PROTECTED |
| Forge XOR/AND | Bitwise gadget lookups | PROTECTED |
| Wrong round constant | Precomputed lookup | PROTECTED |
| Skip rounds | Round counter + latch check | PROTECTED |
| Modular overflow | lhs/rhs decomposition + range checks | PROTECTED |

### 7.2 Attack Surface Analysis (sha256_mem.pil)

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Memory forgery | Permutation to memory | PROTECTED |
| Out-of-bounds | GT lookup + error gating | PROTECTED |
| Invalid state tag | Batched zero-check | PROTECTED |
| Invalid input tag | Per-row check + propagation | PROTECTED |
| Extra input reads | input_addr increment constraint | PROTECTED |

### 7.3 Critical Security Properties

#### 7.3.1 All Bitwise Operations Verified

Every XOR and AND goes through bitwise gadget:
- s0: 2 XORs
- s1: 2 XORs
- S1: 2 XORs
- ch: 2 ANDs + 1 XOR
- S0: 2 XORs
- maj: 3 ANDs + 2 XORs

#### 7.3.2 Modular Addition Soundness

For modulo 2^32 operations:
```pil
sel_compute_w * ((computed_w_lhs * 2**32 + computed_w_rhs) - COMPUTED_W) = 0;
// Range check both limbs
#[RANGE_COMP_W_LHS]
sel_compute_w { two_pow_32, computed_w_lhs, sel_compute_w } in gt.sel_sha256 { ... };
#[RANGE_COMP_W_RHS]
sel_compute_w { two_pow_32, computed_w_rhs, sel_compute_w } in gt.sel_sha256 { ... };
```

#### 7.3.3 Input Address Constraint

```pil
#[CONTINUITY_INPUT_ADDR]
(1 - LATCH_CONDITION) * (input_addr' - (input_addr + sel_is_input_round)) = 0;
```

Prevents arbitrary memory addresses during input loading.

---

## 8. Findings

### No Critical Vulnerabilities Found

Both sha256.pil and sha256_mem.pil are **SOUND**.

### INFO-1: Helper W Array

16-element sliding window for w computation:
```pil
helper_w0, helper_w1, ..., helper_w15
```

Enables efficient access to w[i-16], w[i-15], w[i-7], w[i-2].

### INFO-2: Shared Memory Columns

State read and output write share columns:
```pil
sel_mem_state_or_output = STATE_READ_CONDITION + OUTPUT_WRITE_CONDITION;
```

Saves ~24 columns by reusing addresses/registers.

### INFO-3: Batched Tag Check

8 tag differences batched with powers 2^0, 2^3, ..., 2^21:
- MEM_TAG_U32 = 2, so differences ∈ {-2, ..., 5}
- 3-bit spacing ensures no overlap

### INFO-4: Error Latch Precision

```pil
LATCH_ON_ERROR = 1 - (1 - mem_out_of_range_err) * (1 - sel_invalid_state_tag_err) * (1 - sel_invalid_input_row_tag_err);
```

Uses `sel_invalid_input_row_tag_err` (not propagated) to latch on correct row.

---

## 9. Conclusion

**Status**: SOUND

Both gadgets are **correctly implemented** with:

**sha256.pil**:
- Complete 64-round SHA256 compression
- All rotations verified via GT range checks
- All XOR/AND via bitwise lookups
- Correct modular addition decomposition
- Round constants from precomputed

**sha256_mem.pil**:
- Permutations for all memory operations (state/input/output)
- Comprehensive bounds checking
- Batched state tag validation
- Per-row input tag checking with propagation
- Proper error consolidation and gating

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

### sha256.pil

| Constraint Group | Count | Purpose |
|------------------|-------|---------|
| W expansion (s0) | 5 | Rotation + XOR for s0 |
| W expansion (s1) | 5 | Rotation + XOR for s1 |
| Compression S1 | 5 | Rotation + XOR for S1 |
| Compression ch | 4 | AND/XOR for ch |
| Compression S0 | 5 | Rotation + XOR for S0 |
| Compression maj | 6 | AND/XOR for maj |
| State update | 8 | a-h propagation |
| Output | 8 | Final state + init |
| Range checks | ~40 | Modular arithmetic |

### sha256_mem.pil

| Constraint | Purpose |
|------------|---------|
| CHECK_*_ADDR_IN_RANGE | Bounds checking |
| MEM_OP_[0-7] | State/output permutations |
| MEM_INPUT_READ | Input permutation |
| BATCH_ZERO_CHECK_READ | State tag validation |
| INPUT_TAG_DIFF_CHECK | Input tag validation |
| TAG_ERROR_PROPAGATION | Error lifting |
| CONTINUITY_INPUT_ADDR | Address safety |

## Appendix: Operation Count Per Round

```
W computation (rounds 16-63):
  - 3 rotations (7, 18, 3) → 3 range checks
  - 3 rotations (17, 19, 10) → 3 range checks
  - 4 XORs (s0, s1)
  - 1 modular add → 2 range checks

Compression (all 64 rounds):
  - 3 rotations (6, 11, 25 for S1) → 3 range checks
  - 2 XORs (S1)
  - 2 ANDs (ch)
  - 1 XOR (ch)
  - 3 rotations (2, 13, 22 for S0) → 3 range checks
  - 2 XORs (S0)
  - 3 ANDs (maj)
  - 2 XORs (maj)
  - 2 modular adds → 4 range checks
```
