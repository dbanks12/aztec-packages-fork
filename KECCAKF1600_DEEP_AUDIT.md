# Deep Security Audit: keccakf1600.pil & keccak_memory.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL files: `pil/vm2/keccakf1600.pil` (~1500 lines), `pil/vm2/keccak_memory.pil` (270 lines)
- [x] Located dependencies: bitwise.pil, range_check.pil, memory.pil, precomputed.pil, gt.pil
- [x] Located callers: execution.pil (DISPATCH_TO_KECCAKF1600)

### Phase 2: Understanding
- [x] Documented gadget purposes (permutation, memory I/O)
- [x] Listed all witnesses (25 state words, intermediate states)
- [x] Listed all constraints (theta, rho, pi, chi, iota)
- [x] Understood 24-round structure

### Phase 3: Soundness
- [x] Verified bitwise lookups
- [x] Analyzed rotation constraints
- [x] Checked error handling completeness
- [x] Verified memory permutations

### Phase 4: Completeness
- [x] Reviewed trace shape constraints
- [x] Checked tag error propagation
- [x] Verified round counting

### Phase 5: Integration
- [x] Verified execution dispatch
- [x] Checked keccak_memory interaction
- [x] Verified bitwise accounting

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/keccakf1600.pil` | ~1500 | Keccak-f[1600] permutation (24 rounds) |
| `pil/vm2/keccak_memory.pil` | 270 | Memory slice read/write (25 U64 values) |

---

## 2. Gadget Architecture

### 2.1 keccakf1600.pil Purpose

Implements the Keccak-f[1600] permutation:
- **State**: 25 × 64-bit words (arranged in 5×5 grid)
- **Rounds**: 24 iterations of round function
- **Sub-functions per round**: θ (theta), ρ (rho), π (pi), χ (chi), ι (iota)

### 2.2 Trace Structure

```
| round | sel | start | last | state_in_00..44 | ... intermediate states ... |
|-------|-----|-------|------|-----------------|------------------------------|
|   1   |  1  |   1   |   0  |  input values   | theta → rho → pi → chi → iota |
|   2   |  1  |   0   |   0  |  from iota/chi  | theta → rho → pi → chi → iota |
|  ...  | ... |  ...  |  ... |      ...        |             ...               |
|  24   |  1  |   0   |   1  |  from iota/chi  | OUTPUT (state_iota_00, state_chi_ij) |
```

24 rows per keccak permutation, 1 row if error occurs immediately.

### 2.3 keccak_memory.pil Purpose

Handles memory I/O for keccak state slices:
- Read 25 consecutive U64 values from memory
- Write 25 consecutive U64 values to memory
- Detect tag errors (non-U64 values)

### 2.4 Data Flow

```
execution.pil (DISPATCH_TO_KECCAKF1600)
    ↓ permutation (is)
keccakf1600.start
    ↓ permutation (is) to keccak_memory.start_read
    ↓ permutation (is) to keccak_memory.start_write
keccak_memory.sel
    ↓ permutation (is) to memory.sel_keccak
```

---

## 3. Keccak Round Functions

### 3.1 Theta Function

```pil
// keccakf1600.pil:182-220
// XOR 5 values per column
theta_xor_row_i = state_in_i0 ^ state_in_i1 ^ state_in_i2 ^ state_in_i3 ^ state_in_i4

// Then XOR with rotated column values
state_theta_ij = state_in_ij ^ theta_xor_row_{i-1} ^ ROT(theta_xor_row_{i+1}, 1)
```

Uses bitwise gadget for all XOR operations with lookups.

### 3.2 Rho Function (Rotation)

```pil
// keccakf1600.pil:750-884
// Each state word is rotated by a fixed amount
state_rho_ij = ROT(state_theta_ij, ROT_LEN_ij)

// Rotation verification:
// X = hi * 2^a + low (decomposition)
// Y = low * 2^b + hi (rotated value, where a + b = 64)
// Range check: hi < 2^b OR low < 2^a (whichever is smaller)
```

### 3.3 Pi Function (Permutation)

```pil
// keccakf1600.pil:886-924
// Pure index permutation: OUT[j][2*i + 3*j % 5] = IN[i][j]
pol STATE_PI_00 = STATE_RHO_00;
pol STATE_PI_01 = state_rho_30;
// ... 25 total mappings
```

No constraints needed - just alias definitions.

### 3.4 Chi Function (Non-linear)

```pil
// keccakf1600.pil:926-1139
// state_chi_ij = state_pi_ij ^ ((NOT state_pi_{i+1,j}) & state_pi_{i+2,j})

// NOT computation (algebraic):
state_pi_not_ij = sel_no_error * (2^64 - 1 - STATE_PI_ij);

// AND via bitwise lookup:
#[STATE_PI_AND_00]
sel_no_error { bitwise_and_op_id, state_pi_not_10, state_rho_22, state_pi_and_00, tag_u64 }
in bitwise.start_keccak { ... };

// Final XOR via bitwise lookup:
#[STATE_CHI_00]
sel_no_error { bitwise_xor_op_id, state_theta_00, state_pi_and_00, state_chi_00, tag_u64 }
in bitwise.start_keccak { ... };
```

### 3.5 Iota Function (Round Constant)

```pil
// keccakf1600.pil:1275-1292
#[ROUND_CST]
sel_no_error { round, round_cst } in precomputed.sel_keccak { precomputed.clk, precomputed.keccak_round_constant };

#[STATE_IOTA_00]
sel_no_error { bitwise_xor_op_id, state_chi_00, round_cst, state_iota_00, tag_u64 }
in bitwise.start_keccak { ... };
```

Only state[0][0] is XORed with round constant.

---

## 4. Error Handling

### 4.1 Error Sources

```pil
// keccakf1600.pil:1363-1391
pol commit src_out_of_range_error;  // Source slice out of bounds
pol commit dst_out_of_range_error;  // Destination slice out of bounds
pol commit tag_error;               // Non-U64 tag in input

#[ERROR]
error = 1 - (1 - src_out_of_range_error) * (1 - dst_out_of_range_error) * (1 - tag_error);
```

### 4.2 Bounds Checking

```pil
// keccakf1600.pil:1370-1381
pol HIGHEST_SLICE_ADDRESS = AVM_HIGHEST_MEM_ADDRESS - AVM_KECCAKF1600_STATE_SIZE + 1;

#[SRC_OUT_OF_RANGE_TOGGLE]
start { src_addr, highest_slice_address, src_out_of_range_error }
in gt.sel_others { gt.input_a, gt.input_b, gt.res };

#[DST_OUT_OF_RANGE_TOGGLE]
start { dst_addr, highest_slice_address, dst_out_of_range_error }
in gt.sel_others { gt.input_a, gt.input_b, gt.res };
```

### 4.3 Error Gating

```pil
// keccakf1600.pil:83-85
sel_no_error = sel * (1 - error);

// All round function lookups are gated by sel_no_error
#[THETA_XOR_01]
sel_no_error { ... } in bitwise.start_keccak { ... };
```

---

## 5. Memory Operations

### 5.1 Slice Read (Permutation)

```pil
// keccakf1600.pil:1437-1452
sel_slice_read = start * (1 - src_out_of_range_error) * (1 - dst_out_of_range_error);

#[READ_TO_SLICE]
sel_slice_read { state_in_00, state_in_10, ... state_in_44, clk, src_addr, space_id, tag_error }
is keccak_memory.start_read { ... };
```

### 5.2 Slice Write (Permutation)

```pil
// keccakf1600.pil:1458-1473
sel_slice_write = sel_no_error * last;

#[WRITE_TO_SLICE]
sel_slice_write { state_iota_00, state_chi_10, ... state_chi_44, clk, dst_addr, space_id, round }
is keccak_memory.start_write { ... };
```

**Critical**: Both use permutations (`is`), preventing forged memory operations.

### 5.3 Memory to Trace (keccak_memory.pil)

```pil
// keccak_memory.pil:244-246
#[SLICE_TO_MEM]
sel { clk, space_id, addr, val[0], tag, rw }
is memory.sel_keccak { memory.clk, memory.space_id, memory.address, memory.value, memory.tag, memory.rw };
```

---

## 6. keccak_memory.pil Constraints

### 6.1 Value Shifting

```pil
// keccak_memory.pil:195-242
#[VAL01]
val[1] = (1 - LATCH_CONDITION) * val[0]';
#[VAL02]
val[2] = (1 - LATCH_CONDITION) * val[1]';
// ... up to val[24]
```

Values shift upward through rows, collecting 25 values on start row.

### 6.2 Tag Error Detection

```pil
// keccak_memory.pil:188-193
pol TAG_MIN_U64 = tag - constants.MEM_TAG_U64;
#[SINGLE_TAG_ERROR]
sel * (TAG_MIN_U64 * ((1 - single_tag_error) * (1 - tag_min_u64_inv) + tag_min_u64_inv) - single_tag_error) = 0;
```

Zero-check pattern: `single_tag_error = 1` iff `tag != MEM_TAG_U64`.

### 6.3 Tag Error Propagation

```pil
// keccak_memory.pil:168-172
#[TAG_ERROR_INIT]
last * (tag_error - single_tag_error) = 0;

#[TAG_ERROR_PROPAGATION]
(1 - LATCH_CONDITION) * (tag_error - tag_error') = 0;
```

---

## 7. Soundness Verification

### 7.1 Attack Surface Analysis (keccakf1600.pil)

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Forge XOR/AND result | Bitwise gadget lookups | PROTECTED |
| Wrong rotation | Range check on limbs | PROTECTED |
| Skip rounds | Round increment + WRITE_TO_SLICE checks round=24 | PROTECTED |
| Wrong round constant | Precomputed lookup by round | PROTECTED |
| Out-of-bounds access | GT lookup + error gating | PROTECTED |
| Memory forgery | Permutations to keccak_memory | PROTECTED |

### 7.2 Attack Surface Analysis (keccak_memory.pil)

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Illegal memory operation | Counter propagation from start | PROTECTED |
| Wrong tag | Zero-check on tag difference | PROTECTED |
| Skip tag check | tag_error propagation | PROTECTED |
| Memory forgery | Permutation to memory.sel_keccak | PROTECTED |

### 7.3 Critical Security Properties

#### 7.3.1 All Bitwise Operations Verified

Every XOR and AND operation goes through bitwise gadget lookups:
- 20 XORs for theta (4 per column × 5 columns)
- 25 ANDs for chi
- 25 XORs for chi final
- 1 XOR for iota
- Plus theta_d computation XORs

#### 7.3.2 Rotation Soundness

From comments (keccakf1600.pil:139-165):
- Given X < 2^64 and Y < 2^64
- Range check on smaller limb proves correct rotation
- Mathematical proof provided in comments

#### 7.3.3 Round Count Enforcement

```pil
// The WRITE_TO_SLICE lookup constrains round == 24
sel_slice_write { ..., round } is keccak_memory.start_write { ..., keccak_memory.num_rounds };
// where num_rounds = AVM_KECCAKF1600_NUM_ROUNDS = 24
```

Cannot complete permutation with fewer rounds.

#### 7.3.4 Illegal Memory Write Prevention

From comments (keccakf1600.pil:1420-1435):
- `sel_slice_write == 1` implies `round == 24`
- Round starts at 1 and increments each row
- Requires 24 consecutive valid rows
- Only triggered by legitimate `start` row

---

## 8. Findings

### No Critical Vulnerabilities Found

Both keccakf1600.pil and keccak_memory.pil are **SOUND**.

### INFO-1: Large File Size

keccakf1600.pil is ~1500 lines due to explicit constraints for each of 25 state words across 5 sub-functions. This is correct unrolling, not a security issue.

### INFO-2: Error Short-Circuit

On error at `start` row, `last = 1` immediately (single-row computation):
```pil
#[LAST_ON_ERROR]
error * (last - 1) = 0;
```

This correctly aborts the permutation and returns error.

### INFO-3: Tag Error Early Termination

In keccak_memory, tag error triggers `last = 1`:
```pil
last = 1 - (1 - ctr_end) * (1 - single_tag_error);
```

This stops reading and propagates error upward.

### INFO-4: NOT Computation Efficiency

NOT(x) for 64-bit integers computed algebraically:
```pil
state_pi_not_ij = sel_no_error * (2^64 - 1 - STATE_PI_ij);
```

No lookup needed since result is constrained by subsequent AND lookup.

---

## 9. Conclusion

**Status**: SOUND

Both gadgets are **correctly implemented** with:

**keccakf1600.pil**:
- Complete 24-round Keccak-f[1600] permutation
- All XOR/AND operations via bitwise lookups
- Sound rotation verification via range checks
- Proper round constant lookup from precomputed
- Error handling for bounds and tag errors
- Permutations for memory slice operations

**keccak_memory.pil**:
- Correct value shifting for 25-element slice
- Sound tag error detection and propagation
- Permutation to memory for each read/write
- Proper counter-based trace shape

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

### keccakf1600.pil

| Constraint Group | Count | Purpose |
|------------------|-------|---------|
| Theta XOR | 24 | Column XOR + state XOR |
| Rho Range Check | 24 | Rotation limb verification |
| Chi NOT | 25 | Algebraic NOT |
| Chi AND | 25 | Bitwise AND lookup |
| Chi XOR | 25 | Bitwise XOR lookup |
| Iota | 2 | Round constant lookup + XOR |
| State Propagation | 25 | Next row state_in |
| Memory Slice | 2 | Read/write permutations |
| Error Handling | 5 | Bounds check, error consolidation |

### keccak_memory.pil

| Constraint | Purpose |
|------------|---------|
| CTR_INIT | Counter starts at 1 |
| CTR_INCREMENT | Counter +1 each row |
| CTR_END | Detect counter = 25 |
| SINGLE_TAG_ERROR | Detect non-U64 tag |
| TAG_ERROR_PROPAGATION | Propagate error upward |
| VAL[0-24] | Value shifting |
| SLICE_TO_MEM | Memory permutation |

## Appendix: Round Function Pipeline

```
state_in[25]
    ↓ Theta
state_theta[25] (constrained via bitwise XOR lookups)
    ↓ Rho (rotation)
state_rho[25] (constrained via range checks)
    ↓ Pi (permutation)
STATE_PI[25] (alias only - no constraints)
    ↓ Chi (NOT, AND, XOR)
state_chi[25] (NOT algebraic, AND/XOR via lookups)
    ↓ Iota (XOR with round constant)
state_iota_00 + state_chi[1-24] = next round input OR output
```
