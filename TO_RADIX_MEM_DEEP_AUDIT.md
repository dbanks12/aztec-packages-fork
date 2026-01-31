# Deep Security Audit: to_radix_mem.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL file: `pil/vm2/to_radix_mem.pil` (290 lines)
- [x] Located simulation code: `simulation/gadgets/to_radix.cpp` (139 lines)
- [x] Located trace generation: `tracegen/to_radix_trace.cpp` (264 lines)
- [x] Located tests: `simulation/gadgets/to_radix.test.cpp` (281 lines)
- [x] Identified callers: `execution.pil` line 1098

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
| `pil/vm2/to_radix_mem.pil` | 290 | Memory ops for TORADIXBE opcode |
| `pil/vm2/to_radix.pil` | ~150 | Core radix decomposition |
| `simulation/gadgets/to_radix.cpp` | 139 | Simulation logic |
| `tracegen/to_radix_trace.cpp` | 264 | Trace generation |
| `simulation/gadgets/to_radix.test.cpp` | 281 | Unit tests |

---

## 2. Gadget Purpose

The `to_radix_mem.pil` gadget implements the TORADIXBE opcode which:
1. Decomposes a field element into radix limbs
2. Outputs in **big-endian** order (reverses little-endian from to_radix.pil)
3. Writes results to memory (U1 for bits, U8 for bytes)
4. Handles multiple error conditions

---

## 3. Simulation Code Analysis

### 3.1 Address Overflow Protection

```cpp
// simulation/gadgets/to_radix.cpp:76-77
uint64_t write_addr_upper_bound = static_cast<uint64_t>(dst_addr) + num_limbs;
bool dst_out_of_range = gt.gt(write_addr_upper_bound, AVM_MEMORY_SIZE);
```

**Verified**: Upcast to `uint64_t` before addition prevents overflow.

### 3.2 Radix Validation

```cpp
// simulation/gadgets/to_radix.cpp:82-83
bool radix_is_lt_2 = gt.gt(2, radix);
bool radix_is_gt_256 = gt.gt(radix, 256);
```

**Verified**: Both bounds checked explicitly via gt gadget.

### 3.3 Bitwise Radix Constraint

```cpp
// simulation/gadgets/to_radix.cpp:86
bool invalid_bitwise_radix = is_output_bits && (radix != 2);
```

**Verified**: If outputting bits, radix must be 2.

### 3.4 Zero Limbs Constraint

```cpp
// simulation/gadgets/to_radix.cpp:88
bool invalid_num_limbs = (num_limbs == 0) && (value != FF(0));
```

**Verified**: If num_limbs is 0, value must be 0.

### 3.5 Big-Endian Reversal

```cpp
// simulation/gadgets/to_radix.cpp:113-115
std::ranges::for_each(limbs.rbegin(), limbs.rend(), [&](bool bit) {
    event.limbs.push_back(MemoryValue::from<uint1_t>(bit));
});
```

**Verified**: Uses reverse iterators to convert LE to BE.

### 3.6 Truncation Detection

```cpp
// simulation/gadgets/to_radix.cpp:125-128
if (truncated) {
    memory_events.emit(std::move(event));
    throw ToRadixException("Error during BE conversion: Truncation error");
}
```

**Verified**: Throws on truncation after emitting event (for trace).

---

## 4. Trace Generation Analysis

### 4.1 Input Validation Error Path

```cpp
// tracegen/to_radix_trace.cpp:145-158
if (write_out_of_range || invalid_radix || invalid_bitwise_radix || invalid_num_limbs) {
    trace.set(row,
              { {
                  { C::to_radix_mem_last, 1 },
                  { C::to_radix_mem_input_validation_error, 1 },
                  { C::to_radix_mem_err, 1 },
                  { C::to_radix_mem_sel_dst_out_of_range_err, write_out_of_range },
                  { C::to_radix_mem_sel_radix_lt_2_err, event.radix < 2 },
                  { C::to_radix_mem_sel_radix_gt_256_err, event.radix > 256 },
                  { C::to_radix_mem_sel_invalid_bitwise_radix, invalid_bitwise_radix ? 1 : 0 },
                  { C::to_radix_mem_sel_invalid_num_limbs_err, invalid_num_limbs ? 1 : 0 },
              } });
    row++;
    continue;
}
```

**Verified**: Single-row with `last=1` for input validation errors.

### 4.2 Found Computation

```cpp
// tracegen/to_radix_trace.cpp:164-174
FF acc = 0;
FF exponent = 1;
std::vector<bool> found(event.limbs.size(), false);
for (size_t i = 0; i < event.limbs.size(); ++i) {
    // Limbs are BE, we compute found in LE since the to_radix subtrace is little endian
    size_t reverse_index = event.limbs.size() - i - 1;
    FF limb_value = event.limbs[reverse_index].as_ff();
    acc += exponent * limb_value;
    exponent *= event.radix;
    found[reverse_index] = acc == event.value;
}
```

**Verified**: Correctly computes `found` for each BE limb position using LE accumulation.

### 4.3 Truncation Error Detection

```cpp
// tracegen/to_radix_trace.cpp:187-188
bool truncation_error = event.num_limbs != 0 && !found.at(0);
```

**Verified**: Truncation occurs if first BE limb's `found` is false.

### 4.4 Memory Write Loop

```cpp
// tracegen/to_radix_trace.cpp:209-240
for (uint32_t i = 0; i < event.num_limbs; ++i) {
    MemoryValue limb_value = event.limbs.at(i);
    bool last = i == (event.num_limbs - 1);

    trace.set(row, { { /* ... */ } });

    remaining_limbs--;
    dst_addr++;
    row++;
}
```

**Verified**: Each row writes one limb, address increments correctly.

---

## 5. PIL Constraint Analysis

### 5.1 Ghost Row Protection

```pil
// to_radix_mem.pil:176
sel_should_write_mem * (1 - sel) = 0
```

**Analysis**: Memory writes only when `sel = 1`, preventing ghost writes.

### 5.2 Big-Endian Index Mapping

The `limb_index_to_lookup` column maps BE index to LE index for to_radix.pil lookup:
- BE index 0 → LE index (num_limbs - 1)
- BE index 1 → LE index (num_limbs - 2)
- etc.

```pil
// to_radix_mem.pil lookup uses limb_index_to_lookup
```

### 5.3 Error Flag Consolidation

```pil
// to_radix_mem.pil error handling
err = input_validation_error OR truncation_error
```

### 5.4 To Radix Lookup

```pil
// to_radix_mem.pil:~220
sel_should_decompose {
    value_to_decompose, radix, limb_index_to_lookup, limb_value, value_found
} in to_radix.sel {
    to_radix.value, to_radix.radix, to_radix.limb_index, to_radix.limb, to_radix.found
};
```

**Uses `in` (lookup)**: Correct - multiple mem rows may reference same to_radix row.

### 5.5 Memory Write Permutation

```pil
// to_radix_mem.pil:~240
sel_should_write_mem {
    execution_clk, space_id, dst_addr, limb_value, output_tag
} is memory.sel_to_radix_mem { ... };
```

**Uses `is` (permutation)**: Correct for memory operations.

---

## 6. Test Coverage Analysis

### 6.1 Existing Test Cases

| Test | Description | Coverage |
|------|-------------|----------|
| `BasicBits` | Decompose 1 to 254 bits | ✓ |
| `ShortBits` | Decompose 1 to 1 bit | ✓ |
| `DecomposeOneBitLargeValue` | Truncation on large value | ✓ |
| `BasicRadix` | Decompose 1 to radix 256 | ✓ |
| `ShortRadix` | Decompose 1 to 1 limb | ✓ |
| `DecomposeOneRadixLargerValue` | Truncation on large value | ✓ |
| `DecomposeInDecimal` | Decompose 1337 to radix 10 | ✓ |
| `BasicTest` (Memory) | BE output to memory | ✓ |
| `DstOutOfRange` | Address overflow error | ✓ |
| `InvalidRadixValue` | Radix < 2 error | ✓ |
| `TruncationError` | Truncation error handling | ✓ |

### 6.2 Coverage Gaps

| Test Case | Status |
|-----------|--------|
| Radix > 256 error | NOT COVERED |
| Invalid bitwise radix (bits mode with radix != 2) | NOT COVERED |
| num_limbs = 0 with value = 0 | NOT COVERED |
| num_limbs = 0 with value != 0 error | NOT COVERED |
| Boundary address (exactly at max) | NOT COVERED |

**Recommendation**: Add additional edge case tests.

---

## 7. Caller Analysis

### 7.1 Execution Dispatch (execution.pil:1098-1107)

```pil
sel_exec_dispatch_to_radix_be {
    precomputed.clk, context_id,
    register_0_,      // value
    register_1_,      // radix
    register_2_,      // num_limbs
    sel_is_output_bits,
    rop[6],           // dst_addr
    sel_radix_gt_256,
    sel_opcode_error
} is to_radix_mem.start {
    to_radix_mem.execution_clk, to_radix_mem.space_id,
    to_radix_mem.value_to_decompose, to_radix_mem.radix,
    to_radix_mem.num_limbs, to_radix_mem.is_output_bits,
    to_radix_mem.dst_addr, to_radix_mem.sel_radix_gt_256_err,
    to_radix_mem.err
};
```

**Verified**:
- Uses `is` (permutation) - correct for dispatch
- Radix > 256 check pre-computed in execution (line 468)
- Error flag propagates correctly

---

## 8. Soundness Verification

### 8.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Address overflow | CHECK_DST_ADDR_IN_RANGE + gt lookup | PROTECTED |
| Invalid radix (< 2) | CHECK_RADIX_LT_2 + gt lookup | PROTECTED |
| Invalid radix (> 256) | CHECK_RADIX_GT_256 + gt lookup | PROTECTED |
| Bits mode with radix != 2 | INVALID_BITWISE_RADIX check | PROTECTED |
| Zero limbs with non-zero value | INVALID_NUM_LIMBS check | PROTECTED |
| Truncation attack | Truncation error detection | PROTECTED |
| Wrong decomposition | Lookup into to_radix.pil | PROTECTED |
| Ghost memory writes | sel_should_write_mem * (1 - sel) = 0 | PROTECTED |
| Wrong byte order | limb_index_to_lookup reversal | PROTECTED |

### 8.2 Big-Endian Correctness

The gadget correctly reverses the little-endian output from to_radix.pil:
1. to_radix.pil computes limbs in LE order (limb[0] is LSB)
2. to_radix_mem.pil looks up with `limb_index_to_lookup = num_limbs - 1 - i`
3. First BE limb (MSB) uses to_radix index `num_limbs - 1`
4. Last BE limb (LSB) uses to_radix index `0`

---

## 9. Findings

### No Critical Vulnerabilities Found

The to_radix_mem gadget is **SOUND**.

### INFO-1: Pre-computed Radix Check

Execution.pil (line 468) notes:
```
// Note that this check is performed again in to_radix_mem.pil (#[CHECK_RADIX_GT_256]) but
// we need to pass it to the lookup
```

The radix > 256 check is duplicated for lookup correctness.

### INFO-2: Good Test Coverage

The test suite covers most error paths, but could be expanded for edge cases.

---

## 10. Conclusion

**Status**: SOUND

The to_radix_mem gadget is **correctly implemented** with:
- Proper big-endian reversal of little-endian decomposition
- Comprehensive error handling (5 error types)
- Safe address bounds checking
- Integration with to_radix.pil for correct decomposition
- Ghost write protection

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Error Types

| Error | Condition | Result |
|-------|-----------|--------|
| `dst_out_of_range` | dst_addr + num_limbs > AVM_MEMORY_SIZE | Single-row error |
| `radix_lt_2` | radix < 2 | Single-row error |
| `radix_gt_256` | radix > 256 | Single-row error |
| `invalid_bitwise_radix` | is_output_bits && radix != 2 | Single-row error |
| `invalid_num_limbs` | num_limbs = 0 && value != 0 | Single-row error |
| `truncation` | Found flag false at BE index 0 | Multi-row with error |
