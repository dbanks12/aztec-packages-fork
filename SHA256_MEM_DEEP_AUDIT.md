# Deep Security Audit: sha256_mem.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL file: `pil/vm2/sha256_mem.pil` (460 lines)
- [x] Located simulation code: `simulation/gadgets/sha256.cpp` (216 lines)
- [x] Located trace generation: `tracegen/sha256_trace.cpp` (692 lines)
- [x] Located tests: `simulation/gadgets/sha256.test.cpp` (64 lines)
- [x] Identified callers: `execution.pil` line 1034-1037

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
| `pil/vm2/sha256_mem.pil` | 460 | PIL constraints for memory ops |
| `pil/vm2/sha256.pil` | 600 | Core SHA256 compression (included) |
| `simulation/gadgets/sha256.cpp` | 216 | Simulation logic |
| `simulation/gadgets/sha256.hpp` | 47 | Interface |
| `tracegen/sha256_trace.cpp` | 692 | Trace generation |
| `simulation/gadgets/sha256.test.cpp` | 64 | Tests |

---

## 2. Caller Analysis

### 2.1 Execution Dispatch (execution.pil:1034-1037)

```pil
sel_exec_dispatch_sha256_compression {
    precomputed.clk, context_id, rop[6], rop[4], rop[5], sel_opcode_error
} is sha256.start {
    sha256.execution_clk, sha256.space_id, sha256.output_addr, sha256.state_addr, sha256.input_addr, sha256.err
};
```

**Analysis**: Uses permutation (`is`), which prevents:
- Row insertion (must have matching count on both sides)
- Result forgery (output_addr, state_addr, input_addr come from execution)

### 2.2 Memory Permutations

The gadget uses 9 permutations into memory.pil:
- `MEM_OP_0` through `MEM_OP_7`: 8 parallel state/output memory ops
- `MEM_INPUT_READ`: Sequential input memory reads

All use `is` (permutation) which is correct for memory operations.

---

## 3. Simulation Code Analysis

### 3.1 Error Handling Flow

```cpp
// simulation/gadgets/sha256.cpp:98-105
bool state_addr_out_of_range = gt.gt(static_cast<uint64_t>(state_addr) + 7, AVM_HIGHEST_MEM_ADDRESS);
bool input_addr_out_of_range = gt.gt(static_cast<uint64_t>(input_addr) + 15, AVM_HIGHEST_MEM_ADDRESS);
bool output_addr_out_of_range = gt.gt(static_cast<uint64_t>(output_addr) + 7, AVM_HIGHEST_MEM_ADDRESS);

if (state_addr_out_of_range || input_addr_out_of_range || output_addr_out_of_range) {
    throw Sha256CompressionException("Memory address out of range for sha256 compression.");
}
```

**Verified**: Addresses are upcast to `uint64_t` before addition to prevent overflow.

### 3.2 Modular Arithmetic

```cpp
// simulation/gadgets/sha256.cpp:60-77
MemoryValue Sha256::modulo_sum(std::span<const MemoryValue> values)
{
    uint64_t sum = 0;
    for (const auto& value : values) {
        sum += value.as<uint32_t>();
    }
    uint32_t lo = static_cast<uint32_t>(sum);  // Truncates to 32 bits
    // ...
    return MemoryValue::from<uint32_t>(lo);
}
```

**Verified**: Uses 64-bit accumulator, truncates to 32 bits for modular reduction.

### 3.3 State Tag Validation

```cpp
// simulation/gadgets/sha256.cpp:113-116
if (std::ranges::any_of(state, [](const MemoryValue& val) { return val.get_tag() != MemoryTag::U32; })) {
    throw Sha256CompressionException("Invalid tag for sha256 state values.");
}
```

**Verified**: All 8 state values validated before use.

### 3.4 Input Tag Validation

```cpp
// simulation/gadgets/sha256.cpp:119-125
for (uint32_t i = 0; i < 16; ++i) {
    input.emplace_back(memory.get(input_addr + i));
    if (input[i].get_tag() != MemoryTag::U32) {
        throw Sha256CompressionException("Invalid tag for sha256 input values.");
    }
}
```

**Verified**: Throws on first invalid input tag, consistent with circuit behavior.

---

## 4. Trace Generation Analysis

### 4.1 Batched Tag Check

```cpp
// tracegen/sha256_trace.cpp:407-415
FF batched_tag_check = 0;
FF target_tag = FF(static_cast<uint8_t>(MemoryTag::U32));
for (uint32_t i = 0; i < event.state.size(); i++) {
    FF mem_tag = FF(static_cast<uint8_t>(event.state[i].get_tag()));
    FF state_tag_diff = mem_tag - target_tag;
    FF exponent = FF(1 << (i * 3)); // exponent is 1, 8, 64, 512, ...
    batched_tag_check += state_tag_diff * exponent;
}
```

**Matches PIL** (sha256_mem.pil:358-361):
```pil
pol BATCHED_TAG_CHECK = 2**0 * STATE_TAG_DIFF_0 + 2**3 * STATE_TAG_DIFF_1
                      + 2**6 * STATE_TAG_DIFF_2 + 2**9 * STATE_TAG_DIFF_3
                      + 2**12 * STATE_TAG_DIFF_4 + 2**15 * STATE_TAG_DIFF_5
                      + 2**18 * STATE_TAG_DIFF_6 + 2**21 * STATE_TAG_DIFF_7;
```

**Exponents verified**: 2^(i*3) = 1, 8, 64, 512, 4096, 32768, 262144, 2097152 ✓

### 4.2 Error Propagation

```cpp
// tracegen/sha256_trace.cpp:444-481
for (uint32_t i = 0; i < event.input.size(); i++) {
    // ...
    bool is_last = (i == event.input.size() - 1);
    trace.set(row + i,
              { {
                  // ...
                  { C::sha256_sel_invalid_input_tag_err, invalid_tag_err ? 1 : 0 },
                  { C::sha256_sel_invalid_input_row_tag_err, (is_last && invalid_tag_err) ? 1 : 0 },
                  // ...
              } });
}
```

**Verified**:
- `sel_invalid_input_tag_err` is set on ALL rows when error occurs (for propagation)
- `sel_invalid_input_row_tag_err` is set ONLY on the specific error row

**Matches PIL constraints** TAG_ERROR_INIT and TAG_ERROR_PROPAGATION.

### 4.3 Memory Output Overflow Handling

```cpp
// tracegen/sha256_trace.cpp:607-614
{ C::sha256_memory_register_0_, round_state[0] + state[0] },
{ C::sha256_memory_register_1_, round_state[1] + state[1] },
// ...
```

**Analysis**: Addition of two uint32_t values. If overflow occurs:
- C++ uint32_t addition wraps (modular 2^32)
- This is intentional for SHA256 modular arithmetic
- The PIL uses `output_*_lhs/rhs` columns for witness decomposition

**Matches** compute_sha256_output (line 272-282) which properly decomposes via `into_limbs_with_witness`.

### 4.4 Column Initialization Check

Checked all error paths for proper column initialization:

| Error Path | Columns Set | Status |
|------------|-------------|--------|
| Out of range | sel, start, error flags, latch | ✓ |
| Invalid state tag | All start columns + error flags | ✓ |
| Invalid input tag | Per-row columns + error propagation | ✓ |

**No uninitialized columns found in error paths.**

---

## 5. PIL Constraint Deep Analysis

### 5.1 Ghost Row Protection

```pil
// sha256_mem.pil:116
start * (1 - sel) = 0;  // start => sel
```

**Combined with** START_AFTER_LAST:
```pil
sel' * (start' - LATCH_CONDITION) = 0;
```

This ensures start can only be 1 after a latch (or first row), preventing ghost starts.

### 5.2 Memory Write Protection

```pil
// sha256_mem.pil:246
rw = OUTPUT_WRITE_CONDITION;
```

Where `OUTPUT_WRITE_CONDITION = latch * (1 - err)`.

**Analysis**: Memory writes only occur when:
1. `latch = 1` (end of computation)
2. `err = 0` (no errors)

This prevents writing invalid results on error.

### 5.3 Input Address Increment

```pil
// sha256_mem.pil:145-146
#[CONTINUITY_INPUT_ADDR]
(1 - LATCH_CONDITION) * (input_addr' - (input_addr + sel_is_input_round)) = 0;
```

**Verified in tracegen** (line 522-523):
```cpp
uint64_t round_input_addr = is_an_input_round ? (input_addr + i) : (input_addr + 16);
```

After input rounds (16-63), input_addr stays at `input_addr + 16`.

---

## 6. Test Coverage Analysis

### 6.1 Existing Tests

```cpp
// simulation/gadgets/sha256.test.cpp:26-61
TEST(Sha256CompressionSimulationTest, Sha256Compression)
```

**Coverage**: Basic happy path with sequential addresses.

### 6.2 Missing Test Cases

| Test Case | Status |
|-----------|--------|
| Out-of-range state address | NOT COVERED |
| Out-of-range input address | NOT COVERED |
| Out-of-range output address | NOT COVERED |
| Invalid state tag (not U32) | NOT COVERED |
| Invalid input tag (not U32) | NOT COVERED |
| Boundary addresses (near max) | NOT COVERED |
| All zeros input | NOT COVERED |
| All ones input | NOT COVERED |

**Recommendation**: Add error path tests.

---

## 7. Findings

### FINDING-1: Limited Test Coverage (LOW)

**Description**: The test file only contains a single happy-path test. Error conditions are not tested.

**Impact**: Potential for bugs in error handling paths to go undetected.

**Recommendation**: Add tests for:
- Each error type (out-of-range, invalid tags)
- Boundary conditions

### FINDING-2: No Fuzzer Found (INFO)

**Description**: No fuzzer exists for sha256_mem.pil in `avm_fuzzer/` directory.

**Recommendation**: Consider adding fuzzing coverage for this gadget.

---

## 8. Cross-Reference with Initial Audit

The initial audit (SHA256_MEM_SECURITY_AUDIT.md) correctly identified:
- ✓ Batched tag checking
- ✓ Memory column reuse
- ✓ Error handling structure

**Additional findings from deep audit**:
- Verified trace generation matches PIL constraints
- Verified simulation matches trace generation
- Identified test coverage gaps

---

## 9. Conclusion

**Status**: SOUND

The sha256_mem gadget is **correctly implemented** with:
- Proper constraint coverage for all data paths
- Correct trace generation matching PIL constraints
- Correct simulation logic with proper error handling
- Safe modular arithmetic implementation

**Caveats**:
- Test coverage should be expanded (LOW priority)
- Consider adding fuzzing (INFO)

No soundness or completeness vulnerabilities were found in this deep audit.
