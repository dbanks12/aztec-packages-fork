# Security Audit: merkle_check.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `merkle_check.pil` gadget verifies Merkle tree membership proofs and computes new roots for write operations. It processes one sibling node per row, computing 1 hash (read) or 2 hashes (read+write) per row via Poseidon2.

### Key Characteristics
- Multi-row operation: `tree_height` rows per operation
- Supports both reads (membership proof) and writes (new root computation)
- Uses Poseidon2 hash function for internal nodes
- WARNING: Breaks if `tree_height >= 254`

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/trees/merkle_check.pil` | PIL constraint definitions (235 lines) |

---

## 3. Constraint Analysis

### 3.1 Lifecycle Constraints

**END_IFF_REM_PATH_EMPTY (line 109)**:
```
sel * (PATH_LEN_MIN_ONE * (end * (1 - path_len_min_one_inv) + path_len_min_one_inv) - 1 + end) = 0
```
- `end = 1` iff `path_len = 1`

**COMPUTATION_FINISH_AT_END (line 115)**:
```
sel * (1 - sel') * (1 - end) = 0
```
- Prevents premature termination (truncating before `end = 1`)

**SELECTOR_ON_START_OR_END (line 123)**:
```
(start + end) * (1 - sel) = 0
```
- Both start and end rows must be active

### 3.2 Index Constraints

**NEXT_INDEX_IS_HALVED (line 149)**:
```
sel * (1 - end) * (2 * index' + INDEX_IS_ODD - index) = 0
```
- `index' = index / 2` (integer division)

**FINAL_INDEX_EQUAL_TO_FIRST_BIT (line 160)**:
```
end * (index - INDEX_IS_ODD) = 0
```
- Final index is 0 or 1

### 3.3 Node Ordering

**READ_LEFT_NODE / READ_RIGHT_NODE (lines 184-186)**:
```
read_left_node = index_is_even * (read_node - sibling) + sibling
read_right_node = index_is_even * (sibling - read_node) + read_node
```
- If `index_is_even`: left=node, right=sibling
- If `!index_is_even`: left=sibling, right=node

### 3.4 Hash Lookups

**MERKLE_POSEIDON2_READ (line 207)**:
```
sel { read_left_node, read_right_node, 0, read_output_hash, 2 }
in poseidon2_hash.start { ... }
```

**MERKLE_POSEIDON2_WRITE (line 216)**:
```
write { write_left_node, write_right_node, 0, write_output_hash, 2 }
in poseidon2_hash.start { ... }
```

### 3.5 Propagation and Root Verification

**OUTPUT_HASH_IS_NEXT_ROWS_READ_NODE (line 226)**:
```
(1 - LATCH_CONDITION) * (read_node' - read_output_hash) = 0
```

**READ_OUTPUT_HASH_IS_READ_ROOT / WRITE_OUTPUT_HASH_IS_WRITE_ROOT (lines 232-234)**:
```
end * (read_output_hash - read_root) = 0
end * (write_output_hash - write_root) = 0
```

---

## 4. Soundness Analysis

### 4.1 Attack Surface

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Truncate computation | COMPUTATION_FINISH_AT_END | PROTECTED |
| Skip rows | END_IFF_REM_PATH_EMPTY + path_len decrement | PROTECTED |
| Swap sibling/node | index_is_even + FINAL_INDEX check | PROTECTED |
| Forge hash | Poseidon2 lookup | PROTECTED |
| Wrong root | READ/WRITE_OUTPUT_HASH_IS_ROOT | PROTECTED |

### 4.2 Tree Height Precondition

The gadget requires `tree_height < 254` to prevent field overflow in `2 * index'`. This is a documented precondition and callers must ensure it.

---

## 5. Findings

### No Critical Vulnerabilities Found

The merkle_check gadget is **SOUND**.

### INFO-1: Write Selector Usage Warning

The comment warns: "Never invoke this gadget using `merkle_check.write` as destination selector." The constraint `sel == 1` is not enforced when `write == 1`, so using `write` as a lookup selector would be under-constrained.

---

## 6. Conclusion

**Status**: SOUND

The merkle_check gadget correctly implements Merkle proof verification with proper:
- Index bit decomposition via halving
- Sibling/node ordering based on parity
- Hash chain verification via Poseidon2 lookups
- Root verification at the end of computation
