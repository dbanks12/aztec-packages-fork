# Deep Security Audit: calldata.pil & calldata_hashing.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL files: `pil/vm2/calldata.pil` (102 lines), `pil/vm2/calldata_hashing.pil` (223 lines)
- [x] Located dependencies: poseidon2_hash.pil, precomputed.pil
- [x] Located callers: data_copy.pil, tx.pil

### Phase 2: Understanding
- [x] Documented gadget purposes (calldata storage, hashing)
- [x] Listed all witnesses
- [x] Listed all constraints
- [x] Understood hash verification mechanism

### Phase 3: Soundness
- [x] Verified value lookups
- [x] Analyzed padding constraints
- [x] Checked hash consistency
- [x] Verified context ID ordering

### Phase 4: Completeness
- [x] Reviewed empty calldata handling
- [x] Checked index constraints
- [x] Verified size validation

### Phase 5: Integration
- [x] Verified data_copy interaction
- [x] Checked tx.pil integration
- [x] Verified poseidon2 lookup

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/calldata.pil` | 102 | Calldata value storage |
| `pil/vm2/calldata_hashing.pil` | 223 | Calldata hash verification |

---

## 2. Gadget Architecture

### 2.1 Purpose

**calldata.pil**: Stores calldata values for each context, indexed by (index, context_id). Values are "hints" validated by calldata_hashing.

**calldata_hashing.pil**: Verifies calldata hash and size by:
1. Looking up values from calldata.pil
2. Hashing with poseidon2 (separator prepended)
3. Validating final hash against public inputs

### 2.2 Trace Structures

**calldata.pil:**
```
| index | value  | context_id | latch |
|-------|--------|------------|-------|
|   1   | 0x111  |     1      |   0   |
|   2   | 0x222  |     1      |   0   |
|   3   | 0x333  |     1      |   0   |
|   4   | 0x444  |     1      |   1   |  ← end of context 1
```

**calldata_hashing.pil:**
```
| index[0] | index[1] | index[2] | input[0] | input[1] | input[2] | output_hash | latch | padding |
|----------|----------|----------|----------|----------|----------|-------------|-------|---------|
|    0     |    1     |    2     |   sep    |  0x111   |  0x222   |  cd_hash    |   0   |    0    |
|    3     |    4     |    5     |  0x333   |  0x444   |    0     |  cd_hash    |   1   |    1    |
```

### 2.3 Empty Calldata Handling

Special case in calldata.pil:
```
| index | value | context_id | latch |
|-------|-------|------------|-------|
|   0   |   0   |     id     |   1   |  ← empty calldata
```

---

## 3. calldata.pil Constraints

### 3.1 Index Increment

```pil
// calldata.pil:83-84
pol FIRST_OR_LAST_CALLDATA = precomputed.first_row + latch;
sel * (1 - FIRST_OR_LAST_CALLDATA) * (index' - index - 1) = 0;
```

**Analysis**: Index increments by 1 until latch.

### 3.2 Context ID Continuity

```pil
// calldata.pil:92-93
#[CONTEXT_ID_CONTINUITY]
(1 - FIRST_OR_LAST_CALLDATA) * (context_id - context_id') = 0;
```

**Analysis**: Context ID stays constant within a calldata block.

### 3.3 Context ID Increasing

```pil
// calldata.pil:96-100
diff_context_id = latch * sel' * (context_id' - context_id - 1);

#[RANGE_CHECK_CONTEXT_ID_DIFF]
latch { diff_context_id } in precomputed.sel_range_16 { precomputed.clk };
```

**Analysis**: At latch, `context_id' >= context_id + 1` (difference in [0, 2^16-1]).

---

## 4. calldata_hashing.pil Constraints

### 4.1 Separator Constraint

```pil
// calldata_hashing.pil:90-91
#[START_IS_SEPARATOR]
start * (input[0] - constants.DOM_SEP__PUBLIC_CALLDATA) = 0;
```

**Analysis**: First field is always the domain separator.

### 4.2 Value Lookups

```pil
// calldata_hashing.pil:105-118
#[GET_CALLDATA_FIELD_0]
sel_not_start { index[0], context_id, input[0] }
in calldata.sel { calldata.index, calldata.context_id, calldata.value };

#[GET_CALLDATA_FIELD_1]
sel_not_padding_1 { index[1], context_id, input[1] }
in calldata.sel { ... };

#[GET_CALLDATA_FIELD_2]
sel_not_padding_2 { index[2], context_id, input[2] }
in calldata.sel { ... };
```

**Analysis**: Each non-padding field is looked up from calldata.pil.

### 4.3 Padding Constraints

```pil
// calldata_hashing.pil:139-156
#[PADDED_BY_ZERO_1]
PADDING_1 * input[1] = 0;
#[PADDED_BY_ZERO_2]
PADDING_2 * input[2] = 0;

#[PADDING_CONSISTENCY]
PADDING_1 * sel_not_padding_2 = 0;  // pad_1 => pad_2
#[PADDING_END]
PADDING_2 * (1 - latch) = 0;  // padding only at latch
```

**Analysis**: Padding can only be 0, 1, or 2 fields at the final row.

### 4.4 Final Size Check

```pil
// calldata_hashing.pil:162-167
#[CHECK_FINAL_INDEX]
latch * ( calldata_size - (
    PADDING_1 * index[0] +
    (PADDING_2 - PADDING_1) * index[1] +
    sel_not_padding_2 * index[2]
)) = 0;
```

**Analysis**: Calldata size matches the last non-padding index.

### 4.5 Size vs Calldata Latch

```pil
// calldata_hashing.pil:175-178
#[CHECK_FINAL_SIZE]
latch { calldata_size, context_id }
in calldata.latch { calldata.index, calldata.context_id };
```

**Analysis**: Verifies calldata_size matches the final index in calldata.pil.

### 4.6 Poseidon2 Lookup

```pil
// calldata_hashing.pil:203-222
#[POSEIDON2_HASH]
sel {
    start, latch,
    input[0], input[1], input[2],
    input_len, rounds_rem, output_hash
} in poseidon2_hash.sel { ... };
```

**Analysis**: Every row is verified against poseidon2_hash trace.

---

## 5. Soundness Verification

### 5.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Forge calldata value | Lookups to calldata.pil | PROTECTED |
| Skip value | Index increment constraints | PROTECTED |
| Wrong hash | #[POSEIDON2_HASH] lookup | PROTECTED |
| Wrong size | #[CHECK_FINAL_SIZE] lookup | PROTECTED |
| Padding manipulation | #[PADDING_CONSISTENCY], #[PADDING_END] | PROTECTED |
| Duplicate context_id | #[RANGE_CHECK_CONTEXT_ID_DIFF] | PROTECTED |
| Non-zero padding | #[PADDED_BY_ZERO_*] | PROTECTED |
| Wrong separator | #[START_IS_SEPARATOR] | PROTECTED |

### 5.2 Critical Security Properties

#### 5.2.1 Value Integrity

All calldata values flow through lookups:
1. `calldata_hashing` looks up values from `calldata`
2. `calldata_hashing` looks up hash from `poseidon2_hash`
3. Hash is verified against public inputs (in tx.pil)

#### 5.2.2 Size Integrity

The calldata size is verified by:
1. `#[CHECK_FINAL_INDEX]`: Size matches last non-padding index
2. `#[CHECK_FINAL_SIZE]`: Size matches calldata.pil's final index

#### 5.2.3 Context ID Uniqueness

```pil
diff_context_id = latch * sel' * (context_id' - context_id - 1);
latch { diff_context_id } in precomputed.sel_range_16 { precomputed.clk };
```

The range check ensures `context_id' - context_id - 1 >= 0`, so context IDs strictly increase.

---

## 6. Findings

### No Critical Vulnerabilities Found

Both calldata.pil and calldata_hashing.pil are **SOUND**.

### INFO-1: Values are "Hints"

From calldata.pil comments:
> The values in the calldata columns are really hints. Their correctness is constrained by calldata_hashing.pil

This is correct - calldata_hashing verifies all values via lookups and hash.

### INFO-2: Index Starts at 1

The calldata trace starts at index=1 (index=0 reserved for empty calldata). This is handled correctly in calldata_hashing with the separator at index[0]=0.

### INFO-3: Padding Efficiency

The comment notes a potential optimization:
> We could defer much of the below calculation to the poseidon trace with an additional lookup

This is a performance consideration, not a security issue.

### INFO-4: Rounds Remaining

The `rounds_rem` column ensures correct poseidon round ordering, preventing a prover from swapping round order.

---

## 7. Conclusion

**Status**: SOUND

Both gadgets are **correctly implemented** with:

- Complete value lookup chain from calldata to hash
- Proper padding constraints (0, 1, or 2 fields)
- Domain separator enforcement
- Size validation against both traces
- Context ID uniqueness via range check
- Poseidon2 hash verification

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

### calldata.pil

| Constraint | Purpose |
|------------|---------|
| SEL_TOGGLED_AT_LATCH | latch → sel |
| (index increment) | Index +1 until latch |
| TRACE_CONTINUITY | Contiguous trace |
| CONTEXT_ID_CONTINUITY | ID stable within block |
| RANGE_CHECK_CONTEXT_ID_DIFF | IDs strictly increasing |

### calldata_hashing.pil

| Constraint | Purpose |
|------------|---------|
| TRACE_CONTINUITY | Contiguous trace |
| SEL_TOGGLED_AT_LATCH | latch → sel |
| ID_CONSISTENCY | context_id stable until latch |
| SIZE_CONSISTENCY | size stable until latch |
| START_AFTER_LATCH | New start after each latch |
| START_INDEX_IS_ZERO | Index starts at 0 |
| START_IS_SEPARATOR | First field is separator |
| INDEX_INCREMENTS | Index +3 per row |
| GET_CALLDATA_FIELD_* | Value lookups |
| PADDED_BY_ZERO_* | Padding = 0 |
| PADDING_CONSISTENCY | pad_1 → pad_2 |
| PADDING_END | padding → latch |
| CHECK_FINAL_INDEX | Size = last index |
| CHECK_FINAL_SIZE | Size lookup |
| HASH_CONSISTENCY | Hash stable until latch |
| ROUNDS_DECREMENT | Round counter |
| POSEIDON2_HASH | Hash lookup |

## Appendix: Hash Computation

```
calldata = [v1, v2, v3, v4, v5]
input_len = 6 (5 values + 1 separator)
rounds = ceil(6/3) = 2

Round 1: H(sep, v1, v2)
Round 2: H(v3, v4, v5)
Final hash = output after round 2
```
