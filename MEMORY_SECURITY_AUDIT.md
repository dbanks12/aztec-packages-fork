# Security Audit: memory.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `memory.pil` gadget implements a sorted memory trace that enforces:
- Memory read/write consistency
- Proper initialization of memory values
- Tagged value range checking on writes
- Chronological ordering within each memory address

### Key Characteristics
- Memory entries sorted by (space_id, address, clk, rw) = (global_addr, timestamp)
- Supports multiple memory spaces (16-bit space_id)
- Supports tagged values (U1, U8, U16, U32, U64, U128, FF)
- Range checks non-FF values on write

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/memory.pil` | PIL constraint definitions (265 lines) |
| `barretenberg/cpp/src/barretenberg/vm2/simulation/gadgets/memory.cpp` | Simulation logic |
| `barretenberg/cpp/src/barretenberg/vm2/tracegen/memory_trace.cpp` | Trace generation |
| `barretenberg/cpp/src/barretenberg/vm2/constraining/relations/memory.test.cpp` | Constraint tests |

---

## 3. Constraint Analysis

### 3.1 Trace Structure Constraints

**MEM_CONTIGUOUS (line 185)**:
```
(1 - precomputed.first_row) * (1 - sel) * sel' = 0
```
- After the first row, if `sel = 0` then `sel' = 0`
- Ensures trace is contiguous (no gaps)

**SEL_RNG_CHK (line 190)**:
```
sel_rng_chk = sel * sel'
```
- Active on all rows except the last active row
- Used for diff range checking

### 3.2 Derived Value Constraints

**GLOBAL_ADDR (line 195)**:
```
global_addr = space_id * 2**32 + address
```
- Combines space_id (16-bit) and address (32-bit) into 48-bit unique address

**TIMESTAMP (line 198)**:
```
timestamp = 2 * clk + rw
```
- Combines clock (32-bit) and read/write flag into unique timestamp
- Write (rw=1) has higher timestamp than read (rw=0) at same clock

### 3.3 Sorting Verification

**LAST_ACCESS (line 205)**:
```
sel_rng_chk * (GLOB_ADDR_DIFF * ((1 - last_access) * (1 - glob_addr_diff_inv) + glob_addr_diff_inv) - last_access) = 0
```
- `last_access = 1` iff `global_addr' != global_addr`
- Uses inverse trick for non-zero check

**DIFF (line 212)**:
```
diff = sel_rng_chk * (last_access * GLOB_ADDR_DIFF + (1 - last_access) * (timestamp' - timestamp - rw' * rw))
```
- When `last_access = 1`: diff = global_addr' - global_addr (address transition)
- When `last_access = 0`: diff = timestamp' - timestamp - rw' * rw (same address, time progression)
- The `-rw' * rw` term accounts for simultaneous read+write at same clk

**DIFF_DECOMP (line 216)**:
```
diff = limb[0] + limb[1] * 2**16 + limb[2] * 2**32
```
- Decomposes diff into 3 x 16-bit limbs
- Combined with range checks, proves diff is non-negative (sorted order)

### 3.4 Memory Initialization

**MEMORY_INIT_VALUE (line 229)**:
```
(last_access + precomputed.first_row) * (1 - rw') * value' = 0
```
- First read of a new address must have value = 0

**MEMORY_INIT_TAG (line 231)**:
```
(last_access + precomputed.first_row) * (1 - rw') * (tag' - constants.MEM_TAG_FF) = 0
```
- First read of a new address must have tag = FF

### 3.5 Read-Write Consistency

**READ_WRITE_CONSISTENCY_VALUE (line 239)**:
```
(1 - last_access) * (1 - rw') * (value' - value) = 0
```
- Within same address, reads return the previous value

**READ_WRITE_CONSISTENCY_TAG (line 241)**:
```
(1 - last_access) * (1 - rw') * (tag' - tag) = 0
```
- Within same address, reads return the previous tag

### 3.6 Tag Handling

**TAG_IS_FF (line 248)**:
```
sel * (TAG_FF_DIFF * (sel_tag_is_ff * (1 - tag_ff_diff_inv) + tag_ff_diff_inv) + sel_tag_is_ff - 1) = 0
```
- Proves `sel_tag_is_ff = 1` iff `tag = MEM_TAG_FF`

**SEL_RNG_WRITE (line 252)**:
```
sel_rng_write = rw * (1 - sel_tag_is_ff)
```
- Activates range check for non-FF writes

### 3.7 Lookups

**RANGE_CHECK_LIMB_0/1/2 (lines 221-225)**:
- Range check each 16-bit limb against precomputed table

**TAG_MAX_BITS (lines 256-258)**:
- Lookup tag -> max_bits mapping from precomputed table

**RANGE_CHECK_WRITE_TAGGED_VALUE (lines 262-264)**:
- Range check written values against their tag's bit width

---

## 4. Soundness Analysis

### 4.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Out-of-order trace | diff range checks (48-bit) | PROTECTED |
| Read uninitialized | MEMORY_INIT constraints | PROTECTED |
| Read wrong value | READ_WRITE_CONSISTENCY | PROTECTED |
| Overflow tag range | SEL_RNG_WRITE + range check | PROTECTED |
| Skip permutation | ACTIVE_ROW_NEEDS_PERM_SELECTOR | PROTECTED |

### 4.2 Detailed Soundness Proof

**Claim**: The memory trace correctly enforces sorted order.

**Proof**:
1. diff is computed as either:
   - `global_addr' - global_addr` (when addresses differ), or
   - `timestamp' - timestamp - rw' * rw` (when same address)
2. diff is decomposed into 3 x 16-bit limbs
3. Each limb is range-checked to [0, 2^16)
4. Therefore diff is in [0, 2^48), meaning it's non-negative
5. Non-negative diffs ensure ascending order

**Claim**: Read operations return correct values.

**Proof**:
1. MEMORY_INIT ensures first read of new address returns (0, FF)
2. READ_WRITE_CONSISTENCY ensures subsequent reads return previous value/tag
3. Combined with sorted order, this ensures reads see latest write

### 4.3 Edge Cases

**Simultaneous read+write at same (space_id, addr, clk)**:
- The diff formula uses `-rw' * rw` to handle this case
- When both are writes (rw=rw'=1): diff = timestamp' - timestamp - 1
- When read then write (rw=0, rw'=1): diff = timestamp' - timestamp = 1
- This correctly orders read before write at same clock

---

## 5. Completeness Analysis

### 5.1 Trace Generation Verification

From `memory_trace.cpp`:
```cpp
std::ranges::sort(event_ptrs, [](const auto* lhs, const auto* rhs) { return lhs->operator<(*rhs); });
```
- Events are sorted before trace generation
- Trace starts at row 1 (row 0 reserved)

**Verified**:
- Sorting matches constraint expectations
- All derived values computed correctly
- Inverse columns batch-inverted at end

### 5.2 Potential Completeness Issue

**INFO-1: First Row Handling**

The trace starts at row 1, and row 0 is empty. The constraint:
```
(1 - precomputed.first_row) * (1 - sel) * sel' = 0
```
allows `sel' = 1` when `precomputed.first_row = 1`. This is correct behavior.

---

## 6. Integration Analysis

### 6.1 Permutation Selectors

Memory has 36+ permutation selectors for different callers:
- `sel_addressing_base`, `sel_addressing_indirect[0-6]`
- `sel_register_op[0-5]`
- `sel_data_copy_read`, `sel_data_copy_write`
- `sel_poseidon2_read[0-3]`, `sel_poseidon2_write[0-3]`
- `sel_keccak`, `sel_sha256_read`, `sel_sha256_op[0-7]`
- `sel_ecc_write[0-2]`, `sel_to_radix_write`
- And more...

**ACTIVE_ROW_NEEDS_PERM_SELECTOR (line 144-172)**:
```
sel = sel_addressing_base + sel_addressing_indirect[0] + ... + sel_to_radix_write
```
- Ensures every active row has exactly one permutation selector
- Sum must equal 1 (sel is boolean at line 175)

### 6.2 Dependencies

- **precomputed.pil**: For first_row, range_16, tag_parameters
- **range_check.pil**: For tagged value range checking
- **constants_gen.pil**: For MEM_TAG_FF constant

---

## 7. Test Coverage Assessment

### 7.1 Positive Tests
- Multiple memory events with trace generation
- Contiguous trace verification
- Global address and timestamp derivation
- Last access flag derivation
- Diff calculation (both modes)
- Memory initialization
- Read-write consistency
- Tag handling

### 7.2 Negative Tests
- Non-contiguous trace (MEM_CONTIGUOUS)
- Incorrect sel_rng_chk (SEL_RNG_CHK)
- Wrong global_addr (GLOBAL_ADDR)
- Wrong timestamp (TIMESTAMP)
- Wrong last_access (LAST_ACCESS)
- Wrong diff (DIFF)
- Wrong diff decomposition (DIFF_DECOMP)
- Wrong init value/tag (MEMORY_INIT_VALUE/TAG)
- Read-write consistency violations
- Tag FF detection failures
- Range check lookup failures

---

## 8. Findings

### No Critical Vulnerabilities Found

The memory gadget is **SOUND** and **COMPLETE**.

### INFO-1: Large Permutation Selector Sum

The constraint `ACTIVE_ROW_NEEDS_PERM_SELECTOR` sums 36+ selectors. While this works correctly (all selectors are boolean and mutually exclusive), any new memory caller must add their selector to this sum.

**Recommendation**: Document this requirement clearly for future development.

### INFO-2: 48-bit Address Space

The diff is decomposed into 48 bits (3 x 16-bit limbs), supporting:
- 16-bit space_id
- 32-bit address

This limits the global address space to 2^48. This appears sufficient for current use cases.

---

## 9. Conclusion

**Status**: SOUND

The memory.pil gadget correctly implements a sorted memory trace with:
- Proper initialization semantics
- Read-write consistency
- Tagged value validation
- Integration with multiple memory consumers

The constraint system is complete and no soundness vulnerabilities were identified.

---

## Appendix: Constraint Index

| Constraint | Line | Purpose |
|------------|------|---------|
| MEM_CONTIGUOUS | 185 | Ensure contiguous trace |
| SEL_RNG_CHK | 190 | Derive range check selector |
| GLOBAL_ADDR | 195 | Compute global address |
| TIMESTAMP | 198 | Compute timestamp |
| LAST_ACCESS | 205 | Detect address transitions |
| DIFF | 212 | Compute diff for sorting |
| DIFF_DECOMP | 216 | Decompose diff to limbs |
| RANGE_CHECK_LIMB_0 | 221 | Range check limb 0 |
| RANGE_CHECK_LIMB_1 | 223 | Range check limb 1 |
| RANGE_CHECK_LIMB_2 | 225 | Range check limb 2 |
| MEMORY_INIT_VALUE | 229 | Initialize value to 0 |
| MEMORY_INIT_TAG | 231 | Initialize tag to FF |
| READ_WRITE_CONSISTENCY_VALUE | 239 | Reads return previous value |
| READ_WRITE_CONSISTENCY_TAG | 241 | Reads return previous tag |
| TAG_IS_FF | 248 | Detect FF tag |
| SEL_RNG_WRITE | 252 | Activate write range check |
| TAG_MAX_BITS | 256 | Lookup tag bit width |
| RANGE_CHECK_WRITE_TAGGED_VALUE | 262 | Range check written values |
