# Deep Security Audit: poseidon2_perm.pil, poseidon2_mem.pil, poseidon2_params.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL files: `pil/vm2/poseidon2_perm.pil` (1773 lines), `pil/vm2/poseidon2_mem.pil` (243 lines), `pil/vm2/poseidon2_params.pil` (345 lines)
- [x] Located dependency: poseidon2_hash.pil uses poseidon2_perm
- [x] Located callers: poseidon2_hash.pil, poseidon2_mem.pil, execution.pil

### Phase 2: Understanding
- [x] Documented gadget purposes
- [x] Listed all witnesses
- [x] Listed all constraints
- [x] Understood round structure (4 full + 56 partial + 4 full)

### Phase 3: Soundness
- [x] Verified S-BOX constraints (x^5)
- [x] Verified matrix multiplication
- [x] Analyzed memory operation security
- [x] Checked error handling completeness

### Phase 4: Completeness
- [x] Reviewed trace generation requirements
- [x] Checked error propagation
- [x] Verified output constraints

### Phase 5: Integration
- [x] Verified execution dispatch
- [x] Checked poseidon2_hash interaction
- [x] Verified memory permutation accounting

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/poseidon2_perm.pil` | 1773 | Poseidon2 permutation (64 rounds) |
| `pil/vm2/poseidon2_mem.pil` | 243 | Memory interface for POSEIDON2PERM opcode |
| `pil/vm2/poseidon2_params.pil` | 345 | Round constants and matrix parameters |

---

## 2. Gadget Architecture

### 2.1 poseidon2_perm.pil Purpose

Implements the Poseidon2 permutation for BN254:
- **Total rounds**: 64 (8 full rounds + 56 partial rounds)
- **State size**: 4 field elements
- **Alpha (S-BOX exponent)**: 5

### 2.2 Round Structure

```
Initial External Matrix Layer
    ↓
4 Full Rounds (Rounds 1-4)
    ↓
56 Partial Rounds (Rounds 5-60)
    ↓
4 Full Rounds (Rounds 61-64)
    ↓
Output
```

### 2.3 poseidon2_mem.pil Purpose

Handles memory I/O for the POSEIDON2PERM opcode:
- 4 consecutive memory reads (src, src+1, src+2, src+3)
- 4 consecutive memory writes (dst, dst+1, dst+2, dst+3)
- Error handling for out-of-bounds and invalid tags

### 2.4 Data Flow

```
execution.pil (DISPATCH_TO_POSEIDON2_PERM)
    ↓ permutation (is)
poseidon2_perm_mem.sel
    ↓ lookup (in) to poseidon2_perm
    ↓ permutation (is) to memory (8 operations)
memory.sel_poseidon2_read[0..3], memory.sel_poseidon2_write[0..3]
```

---

## 3. poseidon2_perm.pil Constraints

### 3.1 Initial External Matrix Layer

```pil
// poseidon2_perm.pil:21-50
pol T_0_0 = a_0 + a_1;
pol T_0_1 = a_2 + a_3;
pol T_0_2 = 2 * a_1 + T_0_1;
pol T_0_3 = 2 * a_3 + T_0_0;
sel * (T_0_4 - (4 * T_0_1 + T_0_3)) = 0;
sel * (T_0_5 - (4 * T_0_0 + T_0_2)) = 0;
sel * (T_0_6 - (T_0_3 + T_0_5)) = 0;
sel * (T_0_7 - (T_0_2 + T_0_4)) = 0;
```

**Analysis**: Implements 4x4 Cauchy matrix multiplication on initial state.

### 3.2 Full Round Structure (Rounds 1-4, 61-64)

```pil
// Example: Round 1 (poseidon2_perm.pil:52-82)
// ARK (Add Round Constant)
pol ARK_0_0 = T_0_6 + poseidon2_params.C_0_0;
pol ARK_0_1 = T_0_5 + poseidon2_params.C_0_1;
pol ARK_0_2 = T_0_7 + poseidon2_params.C_0_2;
pol ARK_0_3 = T_0_4 + poseidon2_params.C_0_3;

// S-BOX (In full round ALL inputs are exponentiated)
pol A_0_0 = ARK_0_0 * ARK_0_0 * ARK_0_0 * ARK_0_0 * ARK_0_0;
pol A_0_1 = ARK_0_1 * ARK_0_1 * ARK_0_1 * ARK_0_1 * ARK_0_1;
pol A_0_2 = ARK_0_2 * ARK_0_2 * ARK_0_2 * ARK_0_2 * ARK_0_2;
pol A_0_3 = ARK_0_3 * ARK_0_3 * ARK_0_3 * ARK_0_3 * ARK_0_3;

// External Matrix
pol SUM_0 = A_0_0 + A_0_1 + A_0_2 + A_0_3;
sel * (B_0_0 - (poseidon2_params.MU_0 * A_0_0 + SUM_0)) = 0;
...
```

**Analysis**: All 4 state elements go through S-BOX (x^5), then external matrix.

### 3.3 Partial Round Structure (Rounds 5-60)

```pil
// Example: Round 5 (poseidon2_perm.pil:195-218)
// S-BOX (In partial round ONLY first input is exponentiated)
pol A_4_0 = ARK_4_0 * ARK_4_0 * ARK_4_0 * ARK_4_0 * ARK_4_0;
pol A_4_1 = ARK_4_1;  // No S-BOX
pol A_4_2 = ARK_4_2;  // No S-BOX
pol A_4_3 = ARK_4_3;  // No S-BOX

// Internal Matrix (uses MU_* coefficients)
sel * (B_4_0 - (poseidon2_params.MU_0 * A_4_0 + SUM_4)) = 0;
...
```

**Analysis**: Only first state element goes through S-BOX. Partial round constants C_i_1, C_i_2, C_i_3 are all zero.

### 3.4 Output Constraints

```pil
// poseidon2_perm.pil:1767-1771
sel * (b_0 - T_63_6) = 0;
sel * (b_1 - T_63_5) = 0;
sel * (b_2 - T_63_7) = 0;
sel * (b_3 - T_63_4) = 0;
```

**Analysis**: Output columns tied to final round's matrix output.

---

## 4. poseidon2_mem.pil Constraints

### 4.1 Address Increment

```pil
// poseidon2_mem.pil:61-69
#[READ_ADDR_INCR]
read_address[1] = sel * (read_address[0] + 1);
read_address[2] = sel * (read_address[0] + 2);
read_address[3] = sel * (read_address[0] + 3);

#[WRITE_ADDR_INCR]
write_address[1] = sel * (write_address[0] + 1);
write_address[2] = sel * (write_address[0] + 2);
write_address[3] = sel * (write_address[0] + 3);
```

### 4.2 Bounds Checking

```pil
// poseidon2_mem.pil:77-91
sel * (max_mem_addr - constants.AVM_HIGHEST_MEM_ADDRESS) = 0;

#[CHECK_SRC_ADDR_IN_RANGE]
sel { read_address[3], max_mem_addr, sel_src_out_of_range_err }
in gt.sel_others { gt.input_a, gt.input_b, gt.res };

#[CHECK_DST_ADDR_IN_RANGE]
sel { write_address[3], max_mem_addr, sel_dst_out_of_range_err }
in gt.sel_others { gt.input_a, gt.input_b, gt.res };
```

**Analysis**: Uses GT gadget to check if max addresses exceed memory bounds.

### 4.3 Memory Reads (Permutation)

```pil
// poseidon2_mem.pil:101-147
sel_should_read_mem = sel * (1 - sel_src_out_of_range_err) * (1 - sel_dst_out_of_range_err);

#[POS_READ_MEM_0]
sel_should_read_mem { ... } is memory.sel_poseidon2_read[0] { ... };
#[POS_READ_MEM_1]
sel_should_read_mem { ... } is memory.sel_poseidon2_read[1] { ... };
#[POS_READ_MEM_2]
sel_should_read_mem { ... } is memory.sel_poseidon2_read[2] { ... };
#[POS_READ_MEM_3]
sel_should_read_mem { ... } is memory.sel_poseidon2_read[3] { ... };
```

**Critical**: Uses permutations (`is`) for memory reads, ensuring exact row matching.

### 4.4 Batched Tag Check

```pil
// poseidon2_mem.pil:154-167
pol INPUT_TAG_DIFF_0 = input_tag[0] - constants.MEM_TAG_FF;
pol INPUT_TAG_DIFF_1 = input_tag[1] - constants.MEM_TAG_FF;
pol INPUT_TAG_DIFF_2 = input_tag[2] - constants.MEM_TAG_FF;
pol INPUT_TAG_DIFF_3 = input_tag[3] - constants.MEM_TAG_FF;

pol BATCHED_TAG_CHECK = 2**0 * INPUT_TAG_DIFF_0 + 2**3 * INPUT_TAG_DIFF_1
                      + 2**6 * INPUT_TAG_DIFF_2 + 2**9 * INPUT_TAG_DIFF_3;

#[BATCH_ZERO_CHECK]
BATCHED_TAG_CHECK * ((1 - sel_invalid_tag_err) * (1 - batch_tag_inv) + batch_tag_inv) - sel_invalid_tag_err = 0;
```

**Analysis**: Batches 4 tag checks into one with different powers of 2 (0, 3, 6, 9). Since MEM_TAG_FF is small (6), the differences fit in 3 bits, ensuring no overlap.

### 4.5 Error Consolidation

```pil
// poseidon2_mem.pil:173-174
err = 1 - (1 - sel_src_out_of_range_err) * (1 - sel_dst_out_of_range_err) * (1 - sel_invalid_tag_err);
```

**Analysis**: OR of all error conditions.

### 4.6 Poseidon2 Lookup

```pil
// poseidon2_mem.pil:183-191
sel_should_exec = sel * (1 - err);

#[INPUT_OUTPUT_POSEIDON2_PERM]
sel_should_exec {
    input[0], input[1], input[2], input[3],
    output[0], output[1], output[2], output[3]
} in poseidon2_perm.sel { ... };
```

**Analysis**: Only executes poseidon2 permutation if no errors.

### 4.7 Memory Writes (Permutation)

```pil
// poseidon2_mem.pil:196-242
#[POS_WRITE_MEM_0]
sel_should_exec { ... } is memory.sel_poseidon2_write[0] { ... };
// ... (3 more)
```

**Critical**: Uses permutations (`is`) for memory writes, ensuring exact row matching.

---

## 5. poseidon2_params.pil Constants

### 5.1 Internal Matrix Diagonal

```pil
// poseidon2_params.pil:14-19
pol MU_0 = 7626475329478847982857743246276194948757851985510858890691733676098590062311;
pol MU_1 = 5498568565063849786384470689962419967523752476452646391422913716315471115275;
pol MU_2 = 148936322117705719734052984176402258788283488576388928671173547788498414613;
pol MU_3 = 15456385653678559339152734484033356164266089951521103188900320352052358038155;
```

### 5.2 Round Constants Pattern

- Rounds 1-4 (Full): All 4 constants non-zero
- Rounds 5-60 (Partial): Only C_i_0 non-zero, others are 0
- Rounds 61-64 (Full): All 4 constants non-zero

---

## 6. Soundness Verification

### 6.1 Attack Surface Analysis (poseidon2_perm.pil)

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Wrong S-BOX exponent | Explicit x^5 in constraints | PROTECTED |
| Skip rounds | All 64 rounds constrained in sequence | PROTECTED |
| Wrong matrix | Committed intermediate values with constraints | PROTECTED |
| Wrong output | Output tied to final round T_63_* | PROTECTED |

### 6.2 Attack Surface Analysis (poseidon2_mem.pil)

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Malicious memory read | Permutation to memory.sel_poseidon2_read[*] | PROTECTED |
| Malicious memory write | Permutation to memory.sel_poseidon2_write[*] | PROTECTED |
| Out-of-bounds access | GT lookup + error gating | PROTECTED |
| Invalid tag execution | Batched tag check + error gating | PROTECTED |
| Skip error check | Error consolidation gates sel_should_exec | PROTECTED |

### 6.3 Critical Security Properties

#### 6.3.1 Poseidon2 Permutation Correctness

All 64 rounds are explicitly constrained:
- 4 initial full rounds with all 4 S-BOX applications
- 56 partial rounds with 1 S-BOX application each
- 4 final full rounds with all 4 S-BOX applications
- Total S-BOX applications: 4*4 + 56*1 + 4*4 = 88

The output is deterministically tied to the final round's matrix output.

#### 6.3.2 Memory Operation Security

All 8 memory operations (4 reads, 4 writes) use permutations (`is`):
- This ensures exact row matching with memory trace
- Prevents forged memory operations
- Prevents extra memory accesses

#### 6.3.3 Error Handling Completeness

Three error conditions are checked:
1. `sel_src_out_of_range_err`: Read addresses exceed bounds
2. `sel_dst_out_of_range_err`: Write addresses exceed bounds
3. `sel_invalid_tag_err`: Any input tag is not FF

All errors gate execution via `sel_should_exec = sel * (1 - err)`.

#### 6.3.4 Batched Tag Check Soundness

The batched tag check uses powers 2^0, 2^3, 2^6, 2^9:
- Each tag difference is at most 6 (MEM_TAG_FF = 6)
- Each difference fits in 3 bits
- No overlap between batched values
- Result is 0 iff all tags are FF

---

## 7. Findings

### No Critical Vulnerabilities Found

All poseidon2 gadgets are **SOUND**.

### INFO-1: Large Constraint File

poseidon2_perm.pil is 1773 lines due to unrolled rounds. The comment notes:
> We manually optimized the generated code to speed-up build time

This is a performance optimization, not a security issue.

### INFO-2: Partial Round Constant Optimization

For partial rounds (5-60), only C_i_0 is non-zero:
```pil
pol C_4_1 = 0;
pol C_4_2 = 0;
pol C_4_3 = 0;
```

This matches the Poseidon2 specification for partial rounds.

### INFO-3: Underconstrained Tag on Error

From comments (poseidon2_mem.pil:164-165):
> The input_tag[i]'s columns are under-constrained if `sel_should_read_mem == 0`

This is handled correctly - when reads don't happen, tag checking is irrelevant since error is already set.

### INFO-4: Memory Operation Gating

Read and write operations are gated differently:
- Reads: `sel_should_read_mem = sel * (1 - sel_src_out_of_range_err) * (1 - sel_dst_out_of_range_err)`
- Writes: `sel_should_exec = sel * (1 - err)`

This is correct - we can safely read even if tag is invalid, but must not write.

---

## 8. Conclusion

**Status**: SOUND

All poseidon2 gadgets are **correctly implemented** with:

**poseidon2_perm.pil**:
- Complete 64-round Poseidon2 permutation
- Correct S-BOX (x^5) for full and partial rounds
- Proper matrix multiplications (external and internal)
- Output tied to final round computation

**poseidon2_mem.pil**:
- Permutations for all 8 memory operations
- Complete bounds checking via GT gadget
- Sound batched tag validation
- Error consolidation gating execution

**poseidon2_params.pil**:
- Correct round constants from reference implementation
- Internal matrix diagonal for partial rounds

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

### poseidon2_perm.pil

| Constraint Type | Count | Purpose |
|-----------------|-------|---------|
| Initial Matrix | 4 | External matrix on input |
| Full Round (each) | ~8 | ARK + S-BOX + Matrix |
| Partial Round (each) | ~5 | ARK + S-BOX (1) + Matrix |
| Output | 4 | Tie output to final round |
| Total Rounds | 64 | 4 + 56 + 4 |

### poseidon2_mem.pil

| Constraint | Purpose |
|------------|---------|
| READ_ADDR_INCR | Consecutive read addresses |
| WRITE_ADDR_INCR | Consecutive write addresses |
| CHECK_SRC_ADDR_IN_RANGE | Bounds check reads |
| CHECK_DST_ADDR_IN_RANGE | Bounds check writes |
| POS_READ_MEM_[0-3] | Memory read permutations |
| BATCH_ZERO_CHECK | Batched tag validation |
| INPUT_OUTPUT_POSEIDON2_PERM | Lookup to permutation |
| POS_WRITE_MEM_[0-3] | Memory write permutations |

## Appendix: Round Constant Structure

```
Round 1-4 (Full):   C_i_0, C_i_1, C_i_2, C_i_3 all non-zero
Round 5-60 (Partial): C_i_0 non-zero, C_i_1 = C_i_2 = C_i_3 = 0
Round 61-64 (Full): C_i_0, C_i_1, C_i_2, C_i_3 all non-zero
```

## Appendix: Memory Operation Matrix

```
Operation       | Selector                    | Type
----------------|-----------------------------|-----------
Read input[0]   | sel_should_read_mem         | Permutation
Read input[1]   | sel_should_read_mem         | Permutation
Read input[2]   | sel_should_read_mem         | Permutation
Read input[3]   | sel_should_read_mem         | Permutation
Write output[0] | sel_should_exec             | Permutation
Write output[1] | sel_should_exec             | Permutation
Write output[2] | sel_should_exec             | Permutation
Write output[3] | sel_should_exec             | Permutation
```
