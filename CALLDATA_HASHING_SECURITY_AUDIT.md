# Security Audit: calldata_hashing.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `calldata_hashing.pil` gadget verifies the correctness of calldata hashes. It reads calldata from `calldata.pil`, prepends a domain separator, and produces a Poseidon2 hash used in public inputs.

### Key Characteristics
- Multi-row operation: ceil((calldata_size + 1)/3) rows per hash
- Prepends DOM_SEP__PUBLIC_CALLDATA separator
- Handles empty calldata (produces H(separator))
- Padding with zeros when size % 3 != 0

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/calldata_hashing.pil` | PIL constraint definitions (223 lines) |

---

## 3. Constraint Analysis

### 3.1 Lifecycle Constraints

**TRACE_CONTINUITY (line 44)**:
```
(1 - precomputed.first_row) * (1 - sel) * sel' = 0
```

**SEL_TOGGLED_AT_LATCH (line 51)**:
```
latch * (1 - sel) = 0
```

**START_AFTER_LATCH (line 75)**:
```
sel' * (start' - LATCH_CONDITION) = 0
```

### 3.2 Index Management

**START_INDEX_IS_ZERO (line 87)**:
```
start * index[0] = 0
```

**INDEX_INCREMENTS (line 95)**:
```
sel * (1 - LATCH_CONDITION) * (index[0]' - (index[0] + 3)) = 0
```

**INDEX_INCREMENTS_1/2 (lines 100, 103)**:
```
sel * (index[1] - (index[0] + 1)) = 0
sel * (index[2] - (index[1] + 1)) = 0
```

### 3.3 Domain Separator

**START_IS_SEPARATOR (line 91)**:
```
start * (input[0] - constants.DOM_SEP__PUBLIC_CALLDATA) = 0
```

### 3.4 Calldata Lookups

**GET_CALLDATA_FIELD_0 (line 106)**:
```
sel_not_start { index[0], context_id, input[0] }
in calldata.sel { calldata.index, calldata.context_id, calldata.value };
```

**GET_CALLDATA_FIELD_1/2 (lines 111, 116)**:
- Guarded by `sel_not_padding_1` and `sel_not_padding_2`

### 3.5 Padding Constraints

**PADDED_BY_ZERO_1 (line 140)**:
```
PADDING_1 * input[1] = 0
```

**PADDED_BY_ZERO_2 (line 143)**:
```
PADDING_2 * input[2] = 0
```

**PADDING_CONSISTENCY (line 153)**:
```
PADDING_1 * sel_not_padding_2 = 0
```
- If input[1] is padding, input[2] must also be padding

**PADDING_END (line 156)**:
```
PADDING_2 * (1 - latch) = 0
```
- Padding only occurs at the last row

### 3.6 Size Verification

**CHECK_FINAL_INDEX (line 163)**:
```
latch * ( calldata_size - (
    PADDING_1 * index[0] +
    (PADDING_2 - PADDING_1) * index[1] +
    sel_not_padding_2 * index[2]
)) = 0
```
- Verifies calldata_size matches the final index based on padding

**CHECK_FINAL_SIZE (line 176)**:
```
latch { calldata_size, context_id }
in calldata.latch { calldata.index, calldata.context_id };
```

### 3.7 Hash Input Length

**CALLDATA_HASH_INPUT_LENGTH_FIELDS (line 191)**:
```
sel * (input_len - (calldata_size + 1)) = 0
```
- +1 for the domain separator

### 3.8 Poseidon2 Integration

**POSEIDON2_HASH (line 203)**:
```
sel {
    start, latch, input[0], input[1], input[2],
    input_len, rounds_rem, output_hash
} in poseidon2_hash.sel { ... };
```

---

## 4. Soundness Analysis

### 4.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Skip calldata fields | Sequential index + calldata lookup | PROTECTED |
| Wrong separator | START_IS_SEPARATOR | PROTECTED |
| Wrong size | CHECK_FINAL_SIZE + CHECK_FINAL_INDEX | PROTECTED |
| Non-zero padding | PADDED_BY_ZERO_1/2 | PROTECTED |
| Wrong hash | POSEIDON2_HASH lookup | PROTECTED |
| Empty calldata forge | Special row with index=0, latch=1 | PROTECTED |

### 4.2 Empty Calldata Handling

For empty calldata, a special row exists where:
- `index = 0` and `latch = 1`
- `input[0] = DOM_SEP__PUBLIC_CALLDATA`
- `input[1] = input[2] = 0` (padding)
- `output_hash = H(separator, 0, 0)`

### 4.3 Consistency Checks

Multiple consistency constraints ensure data integrity:
- `ID_CONSISTENCY`: context_id constant within computation
- `SIZE_CONSISTENCY`: calldata_size constant within computation
- `HASH_CONSISTENCY`: output_hash constant within computation

---

## 5. Findings

### No Critical Vulnerabilities Found

The calldata_hashing gadget is **SOUND**.

### INFO-1: Domain Separator Purpose

The domain separator (DOM_SEP__PUBLIC_CALLDATA) prevents collision between:
- Different calldata hashes
- Calldata hashes and other Poseidon2 uses

### INFO-2: Rounds Decrement

**ROUNDS_DECREMENT (line 200)**:
```
sel * ((1 - LATCH_CONDITION) * (rounds_rem' - rounds_rem + 1) + latch * (rounds_rem - 1)) = 0
```
- Ensures proper round ordering for Poseidon2

---

## 6. Conclusion

**Status**: SOUND

The calldata_hashing gadget correctly implements calldata verification with:
- Proper domain separation
- Sequential field access with lookup verification
- Padding enforcement (zeros)
- Size verification from calldata trace

The constraint system is complete and no soundness vulnerabilities were identified.
