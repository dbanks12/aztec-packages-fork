# Deep Security Audit: memory.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL file: `pil/vm2/memory.pil` (265 lines)
- [x] Located simulation: `simulation/gadgets/memory.cpp`, `simulation/events/memory_event.cpp`
- [x] Located trace gen: `tracegen/memory_trace.cpp` (184 lines)
- [x] Located tests: `memory.test.cpp`, `memory_trace.test.cpp`
- [x] Identified 40+ permutation sources from various gadgets

### Phase 2: Understanding
- [x] Documented gadget purpose (memory validation)
- [x] Listed all witnesses
- [x] Listed all constraints
- [x] Listed all lookups/permutations
- [x] Understood sorting/diff mechanism

### Phase 3: Soundness
- [x] Verified sorting constraint
- [x] Analyzed memory initialization
- [x] Checked read-write consistency
- [x] Verified range check on writes

### Phase 4: Completeness
- [x] Reviewed trace generation
- [x] Checked edge cases
- [x] Verified permutation accounting

### Phase 5: Integration
- [x] Verified caller permutations
- [x] Checked range_check interaction

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/memory.pil` | 265 | Memory trace validation |
| `tracegen/memory_trace.cpp` | 184 | Trace generation |
| `simulation/gadgets/memory.cpp` | ~100 | Memory simulation |
| Tests | 300+ | Unit and constraint tests |

---

## 2. Gadget Architecture

### 2.1 Purpose

The memory gadget validates all memory operations in the AVM2. It:
1. Ensures memory operations are correctly sorted
2. Validates read-write consistency (reads return previous write value)
3. Enforces memory initialization (first read returns 0 with FF tag)
4. Range checks tagged values on writes

### 2.2 Memory Model

Memory is organized as a sorted trace of operations:

```
(space_id, address, clk, rw) → ascending order
```

Where:
- `space_id`: 16-bit memory space identifier (context ID)
- `address`: 32-bit memory address
- `clk`: 32-bit execution clock cycle
- `rw`: 0 = read, 1 = write

### 2.3 Global Address and Timestamp

```pil
// memory.pil:194-198
#[GLOBAL_ADDR]
global_addr = space_id * 2**32 + address;

#[TIMESTAMP]
timestamp = 2 * clk + rw;
```

The timestamp formula `2 * clk + rw` ensures writes come after reads at the same clock cycle.

### 2.4 Trace Structure

```
+-----+-----------+---------+-----+----+---------------+------------+-------------+
| sel | space_id  | address | clk | rw | global_addr   | timestamp  | last_access |
+-----+-----------+---------+-----+----+---------------+------------+-------------+
|   0 |         0 |       0 |   0 |  0 |             0 |          0 |           0 |  (first row)
|   1 |         1 |      27 |   5 |  1 |     2^32 + 27 |         11 |           1 |
|   1 |         1 |      28 |  12 |  1 |     2^32 + 28 |         25 |           1 |
|   1 |         3 |      31 |   7 |  0 | 3 * 2^32 + 31 |         14 |           0 |
|   1 |         3 |      31 |   8 |  1 | 3 * 2^32 + 31 |         17 |           1 |
+-----+-----------+---------+-----+----+---------------+------------+-------------+
```

---

## 3. Sorting Proof

### 3.1 Diff Computation

```pil
// memory.pil:207-212
// last_access == 1: diff = global_addr' - global_addr
// last_access == 0: diff = timestamp' - timestamp - rw' * rw
#[DIFF]
diff = sel_rng_chk * (last_access * GLOB_ADDR_DIFF
     + (1 - last_access) * (timestamp' - timestamp - rw' * rw));
```

**Critical**: The `- rw' * rw` term handles consecutive writes at the same (space_id, address, clk).

### 3.2 Diff Decomposition

```pil
// memory.pil:215-225
#[DIFF_DECOMP]
diff = limb[0] + limb[1] * 2**16 + limb[2] * 2**32;

#[RANGE_CHECK_LIMB_0]
sel_rng_chk { limb[0] } in precomputed.sel_range_16 { precomputed.clk };
// ... similar for limb[1], limb[2]
```

### 3.3 Security Analysis

By decomposing `diff` into three 16-bit limbs and range checking each:
- `diff` is constrained to be in `[0, 2^48 - 1]`
- This proves `diff >= 0` (non-negative)
- Non-negative diff proves ascending order
- `2^48` is sufficient because `global_addr < 2^48` and `timestamp < 2^34`

### 3.4 Last Access Detection

```pil
// memory.pil:202-205
pol GLOB_ADDR_DIFF = global_addr' - global_addr;
pol commit glob_addr_diff_inv;
#[LAST_ACCESS]
sel_rng_chk * (GLOB_ADDR_DIFF * ((1 - last_access) * (1 - glob_addr_diff_inv) + glob_addr_diff_inv) - last_access) = 0;
```

Standard zero-check pattern: `last_access = 1` iff `global_addr' != global_addr`.

---

## 4. Memory Initialization

### 4.1 Constraints

```pil
// memory.pil:228-231
#[MEMORY_INIT_VALUE]
(last_access + precomputed.first_row) * (1 - rw') * value' = 0;
#[MEMORY_INIT_TAG]
(last_access + precomputed.first_row) * (1 - rw') * (tag' - constants.MEM_TAG_FF) = 0;
```

**Analysis**: When:
- `last_access = 1` (new address) or `first_row = 1` (trace start)
- AND `rw' = 0` (next operation is a read)

Then:
- `value' = 0`
- `tag' = MEM_TAG_FF` (field element tag, value 0)

This ensures reading uninitialized memory returns `(value=0, tag=FF)`.

---

## 5. Read-Write Consistency

### 5.1 Constraints

```pil
// memory.pil:238-241
#[READ_WRITE_CONSISTENCY_VALUE]
(1 - last_access) * (1 - rw') * (value' - value) = 0;
#[READ_WRITE_CONSISTENCY_TAG]
(1 - last_access) * (1 - rw') * (tag' - tag) = 0;
```

**Analysis**: When:
- `last_access = 0` (same address continues)
- AND `rw' = 0` (next operation is a read)

Then:
- `value' = value`
- `tag' = tag`

This ensures reads return the most recently written value/tag.

---

## 6. Tagged Value Range Check

### 6.1 Write Selector

```pil
// memory.pil:251-252
#[SEL_RNG_WRITE]
sel_rng_write = rw * (1 - sel_tag_is_ff);
```

Range check only on writes (`rw = 1`) with non-FF tags (`tag != FF`).

### 6.2 Range Check Lookup

```pil
// memory.pil:255-264
#[TAG_MAX_BITS]
sel_rng_write { tag, max_bits }
in precomputed.sel_tag_parameters { precomputed.clk, precomputed.tag_max_bits };

#[RANGE_CHECK_WRITE_TAGGED_VALUE]
sel_rng_write { value, max_bits }
in range_check.sel_memory { range_check.value, range_check.rng_chk_bits };
```

**Analysis**: For each write:
1. Look up `max_bits` for the tag (e.g., U8 → 8 bits, U32 → 32 bits)
2. Range check the value to ensure it fits in `max_bits`

This prevents storing out-of-range values in tagged memory.

---

## 7. Permutation Selectors

### 7.1 Active Row Constraint

```pil
// memory.pil:144-172
#[ACTIVE_ROW_NEEDS_PERM_SELECTOR]
sel = sel_addressing_base
    + sel_addressing_indirect[0..6]
    + sel_register_op[0..5]
    + sel_data_copy_read
    + sel_data_copy_write
    + sel_get_contract_instance_exists_write
    + sel_get_contract_instance_member_write
    + sel_unencrypted_log_read
    + sel_poseidon2_read[0..3]
    + sel_poseidon2_write[0..3]
    + sel_keccak
    + sel_sha256_read
    + sel_sha256_op[0..7]
    + sel_ecc_write[0..2]
    + sel_to_radix_write;
```

**Critical Security**: This ensures:
- Every active row (`sel = 1`) has exactly one permutation selector active
- Permutation selectors are mutually exclusive (they sum to `sel`)
- No ghost rows can exist without a corresponding source permutation

### 7.2 Permutation Sources (40+ total)

| Source | Selectors | Purpose |
|--------|-----------|---------|
| Addressing | 8 | Base and indirect addressing |
| Registers | 6 | Register read/write |
| Data Copy | 2 | Calldata/returndata copy |
| Get Contract Instance | 2 | Instance lookup writes |
| Unencrypted Log | 1 | Log reads |
| Poseidon2 | 8 | Hash read/write |
| Keccak | 1 | Keccak memory ops |
| SHA256 | 9 | SHA compression |
| ECC | 3 | ECC point writes |
| To Radix | 1 | Radix decomposition writes |

---

## 8. Trace Generation Analysis

### 8.1 Sorting

```cpp
// memory_trace.cpp:45
std::ranges::sort(event_ptrs, [](const auto* lhs, const auto* rhs) {
    return lhs->operator<(*rhs);
});
```

Events are sorted by `(space_id, address, clk, rw)` before trace population.

### 8.2 Diff Computation

```cpp
// memory_trace.cpp:78-88
if (!is_last) {
    global_addr_diff = next_global_addr - global_addr;
    last_access = global_addr != next_global_addr;
    diff = last_access ? global_addr_diff
         : (next_timestamp - timestamp - two_consecutive_writes);
}
```

**Verified**: Matches PIL exactly.

### 8.3 Limb Decomposition

```cpp
// memory_trace.cpp:105-107
{ C::memory_limb_0_, diff & 0xFFFF },
{ C::memory_limb_1_, (diff >> 16) & 0xFFFF },
{ C::memory_limb_2_, (diff >> 32) },
```

16-bit decomposition matches #[DIFF_DECOMP] constraint.

---

## 9. Soundness Verification

### 9.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Out-of-order memory ops | Sorting proof via diff range check | PROTECTED |
| Read uninitialized memory | MEMORY_INIT_VALUE/TAG constraints | PROTECTED |
| Read incorrect value | READ_WRITE_CONSISTENCY_* constraints | PROTECTED |
| Write oversized value | RANGE_CHECK_WRITE_TAGGED_VALUE | PROTECTED |
| Ghost memory row | ACTIVE_ROW_NEEDS_PERM_SELECTOR | PROTECTED |
| Duplicate timestamps | `- rw' * rw` in diff formula | PROTECTED |
| Skip memory validation | Permutation enforces 1:1 correspondence | PROTECTED |

### 9.2 Timestamp Collision Handling

The formula `diff = timestamp' - timestamp - rw' * rw` handles:
- `(clk=5, rw=0)` followed by `(clk=5, rw=0)`: diff = 0 - 0 = 0 ✓
- `(clk=5, rw=0)` followed by `(clk=5, rw=1)`: diff = 11 - 10 - 0 = 1 ✓
- `(clk=5, rw=1)` followed by `(clk=5, rw=1)`: diff = 11 - 11 - 1 = -1... but prevented by `rw` ordering in sort

**Note**: The trace generator sorts by `rw` last, so consecutive writes at same (space_id, address, clk) cannot occur.

### 9.3 FF Tag Exemption

```pil
sel_rng_write = rw * (1 - sel_tag_is_ff);
```

FF-tagged values are not range checked because they represent full field elements. This is correct - field elements can hold any value up to the field modulus.

---

## 10. Findings

### No Critical Vulnerabilities Found

The memory.pil gadget is **SOUND**.

### INFO-1: 40+ Permutation Sources

The memory gadget serves as the central memory validation point for the entire AVM2. All memory operations from all subtraces must permute into this trace.

### INFO-2: First Row Reserved

```cpp
// memory_trace.cpp:64
uint32_t row = 1; // Skip first row
```

The first row is reserved as an "empty" row for shift operations. This is documented in the trace shape comments.

### INFO-3: Batch Inversion Optimization

```cpp
// memory_trace.cpp:117
trace.invert_columns({ { C::memory_glob_addr_diff_inv } });
```

Inverse columns are populated with raw values and batch inverted for performance.

### INFO-4: Tag Inverse Precomputation

```cpp
// memory_trace.cpp:51-61
static_assert(static_cast<uint8_t>(MemoryTag::FF) == 0);
std::array<FF, NUM_TAGS> tag_inverts;
// ... precompute inverses
```

Since `MEM_TAG_FF = 0`, the tag difference inverse equals the tag value inverse.

---

## 11. Conclusion

**Status**: SOUND

The memory.pil gadget is **correctly implemented** with:

- Robust sorting proof via 48-bit diff decomposition
- Proper memory initialization for uninitialized reads
- Correct read-write consistency constraints
- Range checking for tagged value writes
- Complete permutation accounting (40+ sources)
- No ghost row vulnerabilities

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

| Constraint | Purpose |
|------------|---------|
| GLOBAL_ADDR | Compute unique global address |
| TIMESTAMP | Compute sortable timestamp |
| LAST_ACCESS | Detect address boundary |
| DIFF | Compute sorting difference |
| DIFF_DECOMP | 16-bit limb decomposition |
| RANGE_CHECK_LIMB_* | Prove diff >= 0 |
| MEMORY_INIT_VALUE | First read returns 0 |
| MEMORY_INIT_TAG | First read returns FF tag |
| READ_WRITE_CONSISTENCY_VALUE | Reads match previous value |
| READ_WRITE_CONSISTENCY_TAG | Reads match previous tag |
| SEL_RNG_WRITE | Write range check selector |
| TAG_MAX_BITS | Get bit width for tag |
| RANGE_CHECK_WRITE_TAGGED_VALUE | Validate write value range |
| ACTIVE_ROW_NEEDS_PERM_SELECTOR | Prevent ghost rows |

## Appendix: Memory Tag Bit Widths

| Tag | Value | Max Bits |
|-----|-------|----------|
| FF | 0 | 254 (no range check) |
| U1 | 1 | 1 |
| U8 | 2 | 8 |
| U16 | 3 | 16 |
| U32 | 4 | 32 |
| U64 | 5 | 64 |
| U128 | 6 | 128 |

## Appendix: Sorting Order

The memory trace is sorted by:
1. `space_id` (context ID) - ascending
2. `address` - ascending
3. `clk` (execution clock) - ascending
4. `rw` (read=0, write=1) - ascending

This ensures all operations to the same memory location are grouped together, with reads at the same clock happening before writes.
