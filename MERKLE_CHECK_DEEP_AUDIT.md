# Deep Security Audit: merkle_check.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL file: `pil/vm2/trees/merkle_check.pil` (235 lines)
- [x] Located simulation code: `simulation/gadgets/merkle_check.cpp` (118 lines)
- [x] Located trace generation: `tracegen/merkle_check_trace.cpp` (132 lines)
- [x] Located tests: `merkle_check.test.cpp`, `merkle_check_trace.test.cpp`
- [x] Identified callers: 10+ lookups from 6 tree gadgets

### Phase 2: Understanding
- [x] Documented gadget purpose
- [x] Listed all witnesses
- [x] Listed all constraints
- [x] Listed all lookups
- [x] Understood data flow

### Phase 3: Soundness
- [x] Verified each constraint
- [x] Analyzed attack vectors
- [x] Checked lookup soundness
- [x] Verified selector constraints

### Phase 4: Completeness
- [x] Reviewed trace generation
- [x] Checked for uninitialized variables
- [x] Verified edge case handling
- [x] Reviewed test coverage

### Phase 5: Integration
- [x] Verified caller usage
- [x] Checked cross-gadget interactions

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/trees/merkle_check.pil` | 235 | Core Merkle proof constraints |
| `simulation/gadgets/merkle_check.cpp` | 118 | Simulation logic |
| `tracegen/merkle_check_trace.cpp` | 132 | Trace generation |
| Tests | 200+ | Unit tests |

---

## 2. Gadget Architecture

### 2.1 Purpose

The merkle_check gadget proves:
1. **Read**: Membership of a leaf in a Merkle tree (given root)
2. **Write**: Computes new root after updating a leaf

### 2.2 Multi-Row Structure

For a tree of height H, requires H rows:
- Row 0: Process leaf (start=1)
- Row 1 to H-2: Process intermediate nodes
- Row H-1: Verify root (end=1)

### 2.3 Trace Example (from PIL comments)

```
+-----------+-------+----------+---------+---------------+------------------+-----------+------------+-------------------+------------+-------+-----+-----+
| read_node | index | path_len | sibling | index_is_even | read_output_hash | read_root | write_node | write_output_hash | write_root | start | end | sel |
+-----------+-------+----------+---------+---------------+------------------+-----------+------------+-------------------+------------+-------+-----+-----+
| 27        |    10 |        4 | s0      |             1 | h(27,s0)=n1      | n4        | 28         | h(28,s0)=n5       | n8         |     1 |   0 |   1 |
| n1        |     5 |        3 | s1      |             0 | h(s1,n1)=n2      | n4        | n5         | h(s1,n5)=n6       | n8         |     0 |   0 |   1 |
| n2        |     2 |        2 | s2      |             1 | h(n2,s2)=n3      | n4        | n6         | h(n6,s2)=n7       | n8         |     0 |   0 |   1 |
| n3        |     1 |        1 | s3      |             0 | h(s3,n3)=n4      | n4        | n7         | h(s3,n7)=n8       | n8         |     0 |   1 |   1 |
+-----------+-------+----------+---------+---------------+------------------+-----------+------------+-------------------+------------+-------+-----+-----+
```

---

## 3. Simulation Code Analysis

### 3.1 Membership Check (Read)

```cpp
// simulation/gadgets/merkle_check.cpp:30-46
FF curr_value = leaf_value;
uint64_t curr_index = leaf_index;
for (const auto& sibling : sibling_path) {
    bool index_is_even = (curr_index % 2 == 0);
    curr_value = index_is_even
        ? poseidon2.hash({ curr_value, sibling })
        : poseidon2.hash({ sibling, curr_value });
    curr_index >>= 1;
}

if (curr_index != 0) {
    throw std::runtime_error("Merkle check's final node index must be 0");
}
if (curr_value != root) {
    throw std::runtime_error("Merkle read check failed");
}
```

**Verified**:
- Correct left/right ordering based on index parity
- Final index must be 0 (root)
- Final hash must equal expected root

### 3.2 Write Operation

```cpp
// simulation/gadgets/merkle_check.cpp:86-95
for (const auto& sibling : sibling_path) {
    bool index_is_even = (curr_index % 2 == 0);
    read_value = index_is_even
        ? poseidon2.hash({ read_value, sibling })
        : poseidon2.hash({ sibling, read_value });
    write_value = index_is_even
        ? poseidon2.hash({ write_value, sibling })
        : poseidon2.hash({ sibling, write_value });
    curr_index >>= 1;
}
```

**Verified**: Parallel computation of read path (verify old root) and write path (compute new root).

### 3.3 Precondition

```cpp
BB_ASSERT_LTE(sibling_path.size(), static_cast<size_t>(64),
              "Merkle path length must be less than or equal to 64");
```

**Note**: PIL comments mention tree_height < 254 due to field overflow concerns.

---

## 4. Trace Generation Analysis

### 4.1 Row Population

```cpp
// tracegen/merkle_check_trace.cpp:57-113
for (size_t i = 0; i < full_path_len; ++i) {
    const size_t path_len = full_path_len - i;
    const bool end = path_len == 1;
    const bool start = i == 0;
    const bool index_is_even = current_index_in_layer % 2 == 0;

    const FF read_left_node = index_is_even ? read_node : sibling;
    const FF read_right_node = index_is_even ? sibling : read_node;
    const FF read_output_hash = Poseidon2::hash({ read_left_node, read_right_node });

    // Set trace columns...
    read_node = read_output_hash;
    current_index_in_layer >>= 1;
}
```

**Verified**: Matches simulation logic exactly.

### 4.2 Post-Processing Assertions

```cpp
// tracegen/merkle_check_trace.cpp:115-119
BB_ASSERT_EQ(current_index_in_layer, 0, "Current index in layer is not 0");
BB_ASSERT_EQ(read_node, root, "Read node is not equal to root");
BB_ASSERT_EQ(write_node, new_root, "Write node is not equal to new root");
```

**Verified**: Trace gen verifies consistency.

### 4.3 Batch Inversions

```cpp
trace.invert_columns({ { C::merkle_check_path_len_min_one_inv } });
```

**Verified**: Inverse column for zero-check pattern.

---

## 5. PIL Constraint Analysis

### 5.1 End Condition (Zero-Check)

```pil
// merkle_check.pil:108-109
#[END_IFF_REM_PATH_EMPTY]
sel * (PATH_LEN_MIN_ONE * (end * (1 - path_len_min_one_inv) + path_len_min_one_inv) - 1 + end) = 0;
```

**Analysis**: Standard zero-check pattern enforcing `end = 1` iff `path_len = 1`.

### 5.2 Computation Integrity

```pil
// merkle_check.pil:114-115
#[COMPUTATION_FINISH_AT_END]
sel * (1 - sel') * (1 - end) = 0;
```

**Analysis**: Prevents premature termination. If `sel' = 0` (next row inactive), then `end = 1` (this must be last row).

### 5.3 Start/End Protection

```pil
// merkle_check.pil:122-123
#[SELECTOR_ON_START_OR_END]
(start + end) * (1 - sel) = 0;
```

**Analysis**: Start and end rows must be active (`sel = 1`).

### 5.4 Index Halving

```pil
// merkle_check.pil:148-149
#[NEXT_INDEX_IS_HALVED]
sel * (1 - end) * (2 * index' + INDEX_IS_ODD - index) = 0;
```

**Analysis**: `index' = (index - INDEX_IS_ODD) / 2` - correct tree traversal.

### 5.5 Final Index Constraint

```pil
// merkle_check.pil:159-160
#[FINAL_INDEX_EQUAL_TO_FIRST_BIT]
end * (index - INDEX_IS_ODD) = 0;
```

**Analysis**: At root level, index must be 0 or 1. This also constrains `index_is_even` for the last row.

### 5.6 Node Ordering

```pil
// merkle_check.pil:183-186
#[READ_LEFT_NODE]
read_left_node = index_is_even * (read_node - sibling) + sibling;
#[READ_RIGHT_NODE]
read_right_node = index_is_even * (sibling - read_node) + read_node;
```

**Analysis**:
- If `index_is_even = 1`: left=read_node, right=sibling
- If `index_is_even = 0`: left=sibling, right=read_node

This correctly implements Merkle tree parent computation.

### 5.7 Poseidon2 Lookups

```pil
// merkle_check.pil:206-222
#[MERKLE_POSEIDON2_READ]
sel { read_left_node, read_right_node, 0, read_output_hash, 2 }
in poseidon2_hash.start { ... };

#[MERKLE_POSEIDON2_WRITE]
write { write_left_node, write_right_node, 0, write_output_hash, 2 }
in poseidon2_hash.start { ... };
```

**Uses `in` (lookup)**: Correct - multiple merkle rows may hash same values.

### 5.8 Hash Chaining

```pil
// merkle_check.pil:225-228
#[OUTPUT_HASH_IS_NEXT_ROWS_READ_NODE]
(1 - LATCH_CONDITION) * (read_node' - read_output_hash) = 0;
#[OUTPUT_HASH_IS_NEXT_ROWS_WRITE_NODE]
(1 - LATCH_CONDITION) * (write_node' - write_output_hash) = 0;
```

**Analysis**: Output hash becomes next row's input node.

### 5.9 Root Verification

```pil
// merkle_check.pil:231-234
#[READ_OUTPUT_HASH_IS_READ_ROOT]
end * (read_output_hash - read_root) = 0;
#[WRITE_OUTPUT_HASH_IS_WRITE_ROOT]
end * (write_output_hash - write_root) = 0;
```

**Analysis**: Final hash must equal expected root.

---

## 6. Caller Analysis (10+ Callers)

### 6.1 By Gadget

| Caller | Lookups | Usage |
|--------|---------|-------|
| nullifier_check.pil | 2 | Nullifier tree membership + insertion |
| note_hash_tree_check.pil | 1 | Note hash tree insertion |
| public_data_check.pil | 2 | Public data tree read/write |
| l1_to_l2_message_tree_check.pil | 1 | L1→L2 message tree membership |
| written_public_data_slots_tree_check.pil | 2 | Transient tree checks |
| retrieved_bytecodes_tree_check.pil | 2 | Bytecode tree checks |

### 6.2 Lookup Patterns

**Read Pattern:**
```pil
sel { leaf, index, height, root }
in merkle_check.start {
    merkle_check.read_node, merkle_check.index,
    merkle_check.path_len, merkle_check.read_root
};
```

**Write Pattern:**
```pil
sel { 1, old_leaf, new_leaf, index, height, old_root, new_root }
in merkle_check.start {
    merkle_check.write, merkle_check.read_node, merkle_check.write_node,
    merkle_check.index, merkle_check.path_len,
    merkle_check.read_root, merkle_check.write_root
};
```

---

## 7. Soundness Verification

### 7.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Skip rows | COMPUTATION_FINISH_AT_END | PROTECTED |
| Ghost start/end | SELECTOR_ON_START_OR_END | PROTECTED |
| Wrong left/right order | index_is_even constraints | PROTECTED |
| Forge hash output | MERKLE_POSEIDON2_READ/WRITE lookups | PROTECTED |
| Wrong final root | READ/WRITE_OUTPUT_HASH_IS_ROOT | PROTECTED |
| Premature end | END_IFF_REM_PATH_EMPTY | PROTECTED |
| Index manipulation | NEXT_INDEX_IS_HALVED + FINAL_INDEX | PROTECTED |
| Write without verification | read_output_hash verified against read_root | PROTECTED |

### 7.2 Tree Height Warning

```
WARNING: This gadget will break if used with `tree_height >= 254`
```

This is due to field overflow when computing `2 * index'` in NEXT_INDEX_IS_HALVED. For tree heights < 254, the index value stays well within field bounds.

---

## 8. Findings

### No Critical Vulnerabilities Found

The merkle_check gadget is **SOUND**.

### INFO-1: Fundamental Tree Primitive

This gadget is used by all 6 tree check gadgets for Merkle membership and insertion proofs. Any bug would affect the entire tree subsystem.

### INFO-2: Write Selector Warning

From PIL comments:
> USAGE WARNING: Never invoke this gadget using `merkle_check.write` as destination selector. This would be completely under-constrained as we do not enforce `sel == 1` when `write == 1`.

Callers correctly use `merkle_check.start` as the destination selector.

### INFO-3: Parallel Read/Write Computation

The write operation computes both read path (to verify old root) and write path (to compute new root) simultaneously, sharing the sibling path. This is an efficient design.

---

## 9. Conclusion

**Status**: SOUND

The merkle_check gadget is **correctly implemented** with:
- Proper zero-check for end condition
- Correct index halving with field overflow prevention
- Sound left/right node ordering based on index parity
- Hash verification via poseidon2_hash lookups
- Root verification at end of computation
- Ghost row prevention via SELECTOR_ON_START_OR_END

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

| Constraint | Purpose |
|------------|---------|
| END_IFF_REM_PATH_EMPTY | end=1 iff path_len=1 |
| COMPUTATION_FINISH_AT_END | Prevent premature termination |
| SELECTOR_ON_START_OR_END | start/end on active rows |
| PROPAGATE_READ_ROOT | Root constant through computation |
| PATH_LEN_DECREMENTS | path_len decreases by 1 |
| NEXT_INDEX_IS_HALVED | Index halving for tree traversal |
| FINAL_INDEX_EQUAL_TO_FIRST_BIT | Final index is 0 or 1 |
| READ_LEFT_NODE, READ_RIGHT_NODE | Correct node ordering |
| WRITE_LEFT_NODE, WRITE_RIGHT_NODE | Correct node ordering (write) |
| MERKLE_POSEIDON2_READ/WRITE | Hash verification |
| OUTPUT_HASH_IS_NEXT_ROWS_*_NODE | Hash chaining |
| READ/WRITE_OUTPUT_HASH_IS_ROOT | Root verification |

## Appendix: Index Decomposition

For leaf_index=10 (binary: 1010) in tree of height 4:

| Row | index | INDEX_IS_ODD | index_is_even | Position |
|-----|-------|--------------|---------------|----------|
| 0 | 10 | 0 | 1 (even) | Left child |
| 1 | 5 | 1 | 0 (odd) | Right child |
| 2 | 2 | 0 | 1 (even) | Left child |
| 3 | 1 | 1 | 0 (odd) | Right child |

The index bits determine left/right positioning at each tree level.
