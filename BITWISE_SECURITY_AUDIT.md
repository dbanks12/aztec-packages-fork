# Security Audit: bitwise.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND (after fix)

---

## 1. Overview

The `bitwise.pil` gadget implements AND/OR/XOR operations on non-FF integral types by:
- Decomposing inputs into 8-bit chunks
- Looking up each chunk's operation result in a precomputed bitwise table
- Accumulating the results into the final output

### Key Characteristics
- Multi-row operation: Each operation uses `tag_byte_length` rows (1-16 rows)
- Supports U1, U8, U16, U32, U64, U128 types
- Has error handling for FF tags and tag mismatches
- Used by execution dispatch, keccak, and SHA256 gadgets

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/bitwise.pil` | PIL constraint definitions (278 lines) |
| `barretenberg/cpp/src/barretenberg/vm2/tracegen/bitwise_trace.cpp` | Trace generation |
| `barretenberg/cpp/src/barretenberg/vm2/constraining/relations/bitwise.test.cpp` | Constraint tests (992 lines) |

---

## 3. Constraint Analysis

### 3.1 Core Selectors

**Selector Relationships**:
```
sel * (1 - sel) = 0              // Boolean
start * (1 - start) = 0          // Boolean
start_keccak * (1 - start_keccak) = 0
start_sha256 * (1 - start_sha256) = 0
```

**BITW_START_ONLY_WHEN_SEL (line 106)**: (CRITICAL)
```
(start_keccak + start_sha256) * (1 - sel) = 0
```
- Prevents `start_keccak` or `start_sha256` from being set on inactive rows

### 3.2 Error Handling

**Error Flag Derivation (line 124)**:
```
err = 1 - (1 - sel_tag_mismatch_err) * (1 - sel_tag_ff_err)
```
- err = 1 if either error flag is set

**LAST_ON_ERROR (line 129)**:
```
err * (last - 1) = 0
```
- When err = 1, last must also = 1 (terminate computation)

**INPUT_TAG_CANNOT_BE_FF (line 153)**:
```
start * (TAG_A_DIFF * (sel_tag_ff_err * (1 - tag_a_inv) + tag_a_inv) - 1 + sel_tag_ff_err) = 0
```
- When `start = 1`: `tag_a == FF` iff `sel_tag_ff_err = 1`

**INPUT_TAGS_SHOULD_MATCH (line 160)**:
```
start * (TAG_AB_DIFF * ((1 - sel_tag_mismatch_err) * (1 - tag_ab_diff_inv) + tag_ab_diff_inv) - sel_tag_mismatch_err) = 0
```
- When `start = 1`: `tag_a != tag_b` iff `sel_tag_mismatch_err = 1`

### 3.3 Counter and Selector Logic

**BITW_CTR_DECREMENT (line 186)**:
```
sel * (ctr' - ctr + 1) * (1 - last) = 0
```
- Counter decrements by 1 each row until `last = 1`

**BITW_SEL_CTR_NON_ZERO (line 194)**:
```
ctr * ((1 - sel) * (1 - ctr_inv) + ctr_inv) - sel = 0
```
- `sel = 1` iff `ctr != 0`

**BITW_LAST_FOR_CTR_ONE (line 200)**:
```
sel * ((ctr - 1) * (last * (1 - ctr_min_one_inv) + ctr_min_one_inv) + last - 1) = 0
```
- `last = 1` iff `ctr = 1`

### 3.4 Accumulator Constraints

**BITW_INIT_A/B/C (lines 204-208)**:
```
last * (acc_ia - ia_byte) = 0
last * (acc_ib - ib_byte) = 0
last * (acc_ic - ic_byte) = 0
```
- When `last = 1`, accumulators must equal their byte values

**BITW_ACC_REL_A/B/C (lines 211-215)**:
```
(acc_ia - ia_byte - 256 * acc_ia') * (1 - last) = 0
(acc_ib - ib_byte - 256 * acc_ib') * (1 - last) = 0
(acc_ic - ic_byte - 256 * acc_ic') * (1 - last) = 0
```
- acc_X = X_byte + 256 * acc_X' (shift decomposition)

### 3.5 Lookups

**INTEGRAL_TAG_LENGTH (lines 223-225)**:
```
sel_get_ctr { tag_a, ctr } in precomputed.sel_tag_parameters { precomputed.clk, precomputed.tag_byte_length }
```
- Maps tag to byte length (ctr initialization)
- Only active when `sel_get_ctr = start * (1 - err)`

**BYTE_OPERATIONS (lines 228-230)**:
```
sel { op_id, ia_byte, ib_byte, ic_byte } in precomputed.sel_bitwise { ... }
```
- Looks up 8-bit operation result in precomputed table

---

## 4. Soundness Analysis

### 4.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| FF tag input | INPUT_TAG_CANNOT_BE_FF | PROTECTED |
| Tag mismatch | INPUT_TAGS_SHOULD_MATCH | PROTECTED |
| Skip byte operations | ctr/sel linkage + BYTE_OPERATIONS | PROTECTED |
| Forge keccak XOR | BITW_START_ONLY_WHEN_SEL | PROTECTED |
| Forge SHA256 XOR | BITW_START_ONLY_WHEN_SEL | PROTECTED |
| Truncate counter | BITW_CTR_DECREMENT | PROTECTED |
| Accumulator manipulation | BITW_INIT + BITW_ACC_REL | PROTECTED |

### 4.2 Critical Vulnerability (FIXED)

**PR #19875 Vulnerability**: Before the fix, a malicious prover could:
1. Create a "ghost row" with `sel = 0` but `start_keccak = 1`
2. Set arbitrary `acc_ic` values (not constrained when `sel = 0`)
3. Satisfy keccak/SHA256 XOR lookups with fake results
4. Break hash function security entirely

**Fix Applied (line 106)**:
```
(start_keccak + start_sha256) * (1 - sel) = 0
```

This ensures `start_keccak` and `start_sha256` can only be active when `sel = 1`.

### 4.3 Test Coverage of Vulnerability

The test file includes comprehensive vulnerability tests:
- `VulnerabilityStartKeccakWithoutSel`: Tests ghost row attack
- `VulnerabilityStartSha256WithoutSel`: Tests SHA256 variant
- `VulnerabilityFakeKeccakXorOutput`: Full exploit demonstration
- `VulnerabilityFakeSha256XorOutput`: Full SHA256 exploit

All tests verify the fix prevents the attack:
```cpp
EXPECT_THROW_WITH_MESSAGE((check_relation<bitwise>(trace)), "BITW_START_ONLY_WHEN_SEL");
```

---

## 5. Completeness Analysis

### 5.1 Trace Generation

From `bitwise_trace.cpp`:
```cpp
if (is_tag_ff || is_tag_mismatch) {
    // Error path: single row with err=1, last=1
    trace.set(row, { { ..., { C::bitwise_err, 1 }, { C::bitwise_last, 1 }, ... } });
} else {
    // Normal path: ctr rows from tag_byte_length down to 1
    for (int ctr = start_ctr; ctr > 0; ctr--) {
        // ... fill row with byte decomposition
    }
}
```

**Verified**:
- Error cases set `err = 1`, `last = 1`, `sel_get_ctr = 0`
- Normal cases iterate ctr from `tag_byte_length` to 1
- Precomputed inverses are batch-computed for efficiency

### 5.2 Edge Case: U1 Type

U1 operations use `tag_byte_length = 1`:
- Single row: `ctr = 1`, `last = 1`
- Accumulators equal byte values

---

## 6. Integration Analysis

### 6.1 Callers

| Caller | Selector | Usage |
|--------|----------|-------|
| `execution.pil` | `start` | Dispatch for AND/OR/XOR opcodes |
| `keccakf1600.pil` | `start_keccak` | XOR operations in keccak permutation |
| `sha256.pil` | `start_sha256` | XOR/AND operations in SHA256 compression |

### 6.2 Lookup Usage Patterns

**Execution dispatch** (with error handling):
```
sel_exec_dispatch_bitwise { ..., sel_opcode_error, ... } in bitwise.start { ..., bitwise.err, ... }
```

**Keccak/SHA256** (without error handling):
```
sel_XXX { a, b, c, xor_sel, tag_a } in bitwise.start_XXX { bitwise.acc_ia, bitwise.acc_ib, bitwise.acc_ic, ... }
```

---

## 7. Test Coverage Assessment

### 7.1 Positive Tests
- AND/OR/XOR for all integral types (U1, U8, U16, U32, U64, U128)
- Mixed operations in sequence
- Interactions with precomputed tables

### 7.2 Negative Tests
- Wrong initialization (BITW_INIT_A/B/C)
- Truncated counter (BITW_CTR_DECREMENT)
- Gap in counter (BITW_CTR_DECREMENT)
- Early last flag (BITW_LAST_FOR_CTR_ONE)
- Deactivated row (BITW_SEL_CTR_NON_ZERO)
- Op ID change mid-computation (BITW_OP_ID_REL)
- Wrong accumulation (BITW_ACC_REL_A/B/C)

### 7.3 Error Handling Tests
- FF tag input
- Tag mismatch
- Multiple error conditions
- Error propagation to execution

### 7.4 Vulnerability Tests
- Ghost row attacks for keccak and SHA256
- Full exploit demonstrations with forged XOR outputs

---

## 8. Findings

### FIXED: CRITICAL - Ghost Row XOR Forgery

**Status**: FIXED in current codebase

**Description**: The constraint `(start_keccak + start_sha256) * (1 - sel) = 0` was added to prevent malicious provers from setting `start_keccak = 1` or `start_sha256 = 1` on inactive rows (`sel = 0`).

**Impact Before Fix**: Complete compromise of keccak and SHA256 hash functions. Attacker could prove arbitrary XOR results.

**Location**: `bitwise.pil:106`

---

## 9. Recommendations

### INFO-1: Op ID Constraint Scope

The constraint `#[BITW_OP_ID_REL] (op_id' - op_id) * (1 - last) = 0` ensures op_id is constant within a computation but doesn't prevent changing op_id at boundaries. This is correct behavior but worth noting.

### INFO-2: Counter Upper Bound

The code comment mentions ctr could theoretically be set to any value up to 31 if relaxed. The current implementation restricts it via the `INTEGRAL_TAG_LENGTH` lookup, which is appropriate.

---

## 10. Conclusion

**Status**: SOUND (after vulnerability fix)

The bitwise.pil gadget correctly implements AND/OR/XOR operations with:
- Proper 8-bit decomposition and lookup
- Comprehensive error handling for invalid tags
- Critical protection against ghost row attacks

The vulnerability fix at line 106 is essential for security. The test suite includes full exploit demonstrations that verify the fix works correctly.

---

## Appendix: Constraint Index

| Constraint | Line | Purpose |
|------------|------|---------|
| BITW_START_ONLY_WHEN_SEL | 106 | Prevent ghost row attacks |
| LAST_ON_ERROR | 129 | Error terminates computation |
| RES_TAG_SHOULD_MATCH_INPUT | 145 | Output tag = input tag |
| INPUT_TAG_CANNOT_BE_FF | 153 | Detect FF tag error |
| INPUT_TAGS_SHOULD_MATCH | 160 | Detect tag mismatch |
| BITW_OP_ID_REL | 182 | Op ID constant within computation |
| BITW_CTR_DECREMENT | 186 | Counter decrements by 1 |
| BITW_SEL_CTR_NON_ZERO | 194 | sel iff ctr != 0 |
| BITW_LAST_FOR_CTR_ONE | 200 | last iff ctr = 1 |
| BITW_INIT_A | 204 | Initialize acc_ia |
| BITW_INIT_B | 206 | Initialize acc_ib |
| BITW_INIT_C | 208 | Initialize acc_ic |
| BITW_ACC_REL_A | 211 | Accumulator relation A |
| BITW_ACC_REL_B | 213 | Accumulator relation B |
| BITW_ACC_REL_C | 215 | Accumulator relation C |
| INTEGRAL_TAG_LENGTH | 223 | Lookup tag -> byte length |
| BYTE_OPERATIONS | 228 | Lookup 8-bit operation result |
