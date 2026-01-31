# Deep Security Audit: keccak_memory.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL file: `pil/vm2/keccak_memory.pil` (270 lines)
- [x] Located simulation code: `simulation/gadgets/keccakf1600.cpp` (243 lines)
- [x] Located trace generation: `tracegen/keccakf1600_trace.cpp` (809 lines)
- [x] Located tests: `simulation/gadgets/keccakf1600.test.cpp`
- [x] Identified callers: `keccakf1600.pil` (virtual relationship)

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
| `pil/vm2/keccak_memory.pil` | 270 | Memory slice operations for Keccak-f1600 |
| `pil/vm2/keccakf1600.pil` | ~1200 | Keccak permutation (caller) |
| `simulation/gadgets/keccakf1600.cpp` | 243 | Simulation logic |
| `tracegen/keccakf1600_trace.cpp` | 809 | Trace generation |

---

## 2. Gadget Architecture

### 2.1 Purpose

This gadget handles memory read/write operations for Keccak-f1600 permutation:
- **Read slice**: 25 contiguous U64 memory values (input state)
- **Write slice**: 25 contiguous U64 memory values (output state)

### 2.2 Multi-Row Value Shifting

Uses a "triangle" pattern to shift values from sequential rows to horizontal layout:

```
Row 1:  val_0_=43   val_1_=267  val_2_=17  ... val_24_=238
Row 2:  val_0_=267  val_1_=17   val_2_=?   ... val_24_=0
Row 3:  val_0_=17   ...
...
Row 25: val_0_=238  val_1..24_=0
```

The constraint `val[k+1] = (1 - LATCH_CONDITION) * val[k]'` propagates values upward.

---

## 3. Simulation Code Analysis

### 3.1 Address Range Checking

```cpp
// simulation/gadgets/keccakf1600.cpp:77-82
constexpr MemoryAddress HIGHEST_SLICE_ADDRESS = AVM_HIGHEST_MEM_ADDRESS - AVM_KECCAKF1600_STATE_SIZE + 1;

bool src_out_of_range = gt.gt(static_cast<uint128_t>(src_addr), static_cast<uint128_t>(HIGHEST_SLICE_ADDRESS));
bool dst_out_of_range = gt.gt(static_cast<uint128_t>(dst_addr), static_cast<uint128_t>(HIGHEST_SLICE_ADDRESS));
```

**Verified**: Uses `uint128_t` to prevent overflow in comparison.

### 3.2 Sequential Tag Validation

```cpp
// simulation/gadgets/keccakf1600.cpp:101-114
for (size_t k = 0; k < AVM_KECCAKF1600_STATE_SIZE; k++) {
    const auto addr = src_addr + static_cast<MemoryAddress>(k);
    const MemoryValue& mem_val = memory.get(addr);
    const MemoryTag tag = mem_val.get_tag();
    src_mem_values[k] = mem_val;

    if (tag != MemoryTag::U64) {
        keccakf1600_event.tag_error = true;
        keccakf1600_event.src_mem_values = src_mem_values;
        throw KeccakF1600Exception(...);
    }
}
```

**Verified**:
- Tag check is performed sequentially
- First error terminates loop (early termination)
- All values up to error are captured in event

### 3.3 Keccak Layout

```cpp
// simulation/gadgets/keccakf1600.cpp:119-123
// Standard Keccak layout: memory[(y * 5) + x] = A[x][y], so linear index k maps to (x=k%5, y=k/5)
for (size_t k = 0; k < AVM_KECCAKF1600_STATE_SIZE; k++) {
    state_input_values[k % 5][k / 5] = src_mem_values[k];
}
```

**Verified**: Matches standard Keccak specification for state layout.

---

## 4. Trace Generation Analysis

### 4.1 Value Shifting Implementation

```cpp
// tracegen/keccakf1600_trace.cpp:471-474
// We get a "triangle" when shifting values to their columns from val_0_ bottom-up.
for (size_t j = i; j < num_rows; j++) {
    trace.set(MEM_VAL_COLS.at(j - i), row, slice_ff[j]);
}
```

**Verified**: Creates correct triangle pattern where:
- Row 0 has all 25 values in val_0_ through val_24_
- Row 1 has 24 values in val_0_ through val_23_
- ...
- Row 24 has 1 value in val_0_

This matches the PIL constraint pattern.

### 4.2 Tag Error Handling

```cpp
// tracegen/keccakf1600_trace.cpp:426-436
for (size_t k = 0; k < AVM_KECCAKF1600_STATE_SIZE; k++) {
    const auto& mem_val = event.src_mem_values[k];
    slice_ff[k] = mem_val.as_ff();
    tags[k] = mem_val.get_tag();
    if (tags[k] != MemoryTag::U64) {
        single_tag_errors.at(k) = true;
        num_rows = k + 1;  // Early termination
        break;
    }
}
```

**Verified**:
- Sets `single_tag_error` only on the error row
- Truncates `num_rows` to stop at error
- Remaining values correctly zero-filled

### 4.3 Tag Error Propagation

```cpp
// tracegen/keccakf1600_trace.cpp:438-439
std::array<bool, AVM_KECCAKF1600_STATE_SIZE> tag_errors;
tag_errors.fill(single_tag_errors.at(num_rows - 1));
```

**Verified**: If error occurred at row `k`, all rows 0 to k have `tag_error = true`.

---

## 5. PIL Constraint Deep Analysis

### 5.1 Counter Control Flow

```pil
#[CTR_INIT]
(start_read + start_write) * (ctr - 1) = 0;
```
- Start rows must have `ctr = 1`

```pil
#[CTR_INCREMENT]
sel * (1 - LATCH_CONDITION) * (ctr' - ctr - 1) = 0;
```
- Counter increments by 1 each row unless latch

```pil
#[CTR_END]
sel * ((constants.AVM_KECCAKF1600_STATE_SIZE - ctr) * (ctr_end * (1 - state_size_min_ctr_inv) + state_size_min_ctr_inv) + ctr_end - 1) = 0;
```
- `ctr_end = 1` iff `ctr = 25`

### 5.2 Last Row Definition

```pil
#[LAST]
last = 1 - (1 - ctr_end) * (1 - single_tag_error);
```
- `last = ctr_end OR single_tag_error`
- Computation terminates on counter end OR tag error

### 5.3 Value Shifting Constraints

```pil
#[VAL01]
val[1] = (1 - LATCH_CONDITION) * val[0]';
// ... through
#[VAL24]
val[24] = (1 - LATCH_CONDITION) * val[23]';
```

**Analysis**:
- When `LATCH_CONDITION = 0`: `val[k+1] = val[k]'` (shift from next row)
- When `LATCH_CONDITION = 1`: `val[k+1] = 0` (boundary condition)

This creates the triangle pattern where start row has all 25 values.

### 5.4 Tag Error Zero-Check

```pil
#[SINGLE_TAG_ERROR]
sel * (TAG_MIN_U64 * ((1 - single_tag_error) * (1 - tag_min_u64_inv) + tag_min_u64_inv) - single_tag_error) = 0;
```

**Verified**: Standard zero-check pattern:
- `single_tag_error = 1` iff `tag != U64`

### 5.5 Ghost Row Prevention

The PIL includes an extensive comment (lines 252-269) explaining ghost row prevention:

1. `sel == 1` implies `ctr != 0` (by SEL_CTR_NON_ZERO)
2. Tracing backwards, we either hit:
   - LATCH_CONDITION row where START_AFTER_LATCH requires `start_read | start_write`
   - Which forces `ctr = 1` by CTR_INIT

Therefore, ghost rows with `sel = 1` cannot exist.

---

## 6. Memory Permutation Analysis

```pil
#[SLICE_TO_MEM]
sel { clk, space_id, addr, val[0], tag, rw }
is memory.sel_keccak { memory.clk, memory.space_id, memory.address, memory.value, memory.tag, memory.rw };
```

**Analysis**:
- Uses `is` (permutation) - correct for memory operations
- Each row performs one memory operation
- Memory value comes from `val[0]` (current row's first value)
- Tag comes from memory read

---

## 7. Soundness Verification

### 7.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Skip memory reads | Sequential counter + permutation | PROTECTED |
| Forge memory values | Permutation into memory trace | PROTECTED |
| Wrong tag check | SINGLE_TAG_ERROR zero-check | PROTECTED |
| Ghost memory ops | Counter chain + START_AFTER_LATCH | PROTECTED |
| Early termination bypass | LAST constraint | PROTECTED |
| Value shifting attack | Cascade of VAL constraints | PROTECTED |

### 7.2 Critical Invariants

1. **Counter Chain**: Every active row is part of a 1-to-25 counter chain
2. **Value Triangle**: Values shift correctly through constraint cascade
3. **Tag Propagation**: Error propagates from error row to start row
4. **Memory Integration**: All 25 values hit memory trace via permutation

---

## 8. Findings

### No Critical Vulnerabilities Found

The keccak_memory gadget is **SOUND**.

### INFO-1: Precondition on Address Range

```
// Precondition: We assume the passed offset being such that offset + 24 < 2^32
```

This precondition is verified by `keccakf1600.pil` via GT lookups:
- `lookup_keccakf1600_src_out_of_range_toggle_settings`
- `lookup_keccakf1600_dst_out_of_range_toggle_settings`

### INFO-2: Write Cannot Fail

```pil
#[NO_TAG_ERROR_ON_WRITE]
rw * single_tag_error = 0;
```

Write operations assume values are valid U64. This is safe because:
- Write values come from completed Keccak rounds
- Keccak output is verified via bitwise lookups

---

## 9. Test Coverage Analysis

### 9.1 Existing Tests

`simulation/gadgets/keccakf1600.test.cpp` contains permutation tests.

### 9.2 Coverage Gaps

| Test Case | Status |
|-----------|--------|
| Tag error at position 0 | NOT COVERED |
| Tag error at position 24 | NOT COVERED |
| Out of range src | NOT COVERED |
| Out of range dst | NOT COVERED |
| Sequential tag errors | NOT COVERED |

**Recommendation**: Add explicit error path tests for keccak_memory.

---

## 10. Cross-Reference with Initial Audit

The initial audit (KECCAK_MEMORY_SECURITY_AUDIT.md) identified:
- ✓ Multi-row value shifting
- ✓ Early termination on tag error

**Additional findings from deep audit**:
- Verified simulation matches trace generation
- Verified counter chain prevents ghost rows
- Confirmed value triangle is sound

---

## 11. Conclusion

**Status**: SOUND

The keccak_memory gadget is **correctly implemented** with:
- Proper counter-based lifecycle management
- Sound value shifting via constraint cascade
- Correct tag error handling with early termination
- Ghost row prevention via counter chain

No soundness or completeness vulnerabilities were identified.

---

## Appendix: Constraint Summary

| Constraint | Purpose |
|------------|---------|
| CTR_INIT | Start rows have ctr=1 |
| CTR_INCREMENT | Counter increases by 1 |
| CTR_END | ctr_end=1 iff ctr=25 |
| LAST | last = ctr_end OR single_tag_error |
| START_AFTER_LATCH | Forces start after termination |
| VAL01-VAL24 | Value shifting cascade |
| SINGLE_TAG_ERROR | Zero-check for tag != U64 |
| TAG_ERROR_INIT | Error init at last row |
| TAG_ERROR_PROPAGATION | Error propagates upward |
| SLICE_TO_MEM | Memory permutation |
