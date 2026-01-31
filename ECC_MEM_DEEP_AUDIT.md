# Deep Security Audit: ecc_mem.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL file: `pil/vm2/ecc_mem.pil` (225 lines)
- [x] Located simulation code: `simulation/gadgets/ecc.cpp` (175 lines)
- [x] Located trace generation: `tracegen/ecc_trace.cpp` (364 lines)
- [x] Located tests: `simulation/gadgets/ecc.test.cpp` (279 lines)
- [x] Located fuzzer: `avm_fuzzer/harness/ecc.fuzzer.cpp` (338 lines)
- [x] Identified callers: `execution.pil` line 1050

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
| `pil/vm2/ecc_mem.pil` | 225 | Memory ops for ECADD opcode |
| `pil/vm2/ecc.pil` | ~200 | Core ECC point addition |
| `simulation/gadgets/ecc.cpp` | 175 | Simulation logic |
| `tracegen/ecc_trace.cpp` | 364 | Trace generation |
| `simulation/gadgets/ecc.test.cpp` | 279 | Unit tests |
| `avm_fuzzer/harness/ecc.fuzzer.cpp` | 338 | Fuzzer |

---

## 2. Simulation Code Analysis

### 2.1 On-Curve Check (simulation)

```cpp
// simulation/gadgets/ecc.cpp:137-139
if (!p.on_curve() || !q.on_curve()) {
    throw InternalEccException("One of the points is not on the curve");
}
```

**Verified**: Uses `on_curve()` method from EmbeddedCurvePoint which checks Y^2 = X^3 - 17.

### 2.2 Address Overflow Protection

```cpp
// simulation/gadgets/ecc.cpp:131-134
uint64_t max_write_address = static_cast<uint64_t>(dst_address) + 2;
if (gt.gt(max_write_address, AVM_HIGHEST_MEM_ADDRESS)) {
    throw InternalEccException("dst address out of range");
}
```

**Verified**: Upcast to `uint64_t` before addition prevents overflow.

### 2.3 Infinity Point Normalization

```cpp
// simulation/gadgets/ecc.cpp:142-143
EmbeddedCurvePoint p_input = p.is_infinity() ? EmbeddedCurvePoint::infinity() : p;
EmbeddedCurvePoint q_input = q.is_infinity() ? EmbeddedCurvePoint::infinity() : q;
```

**Verified**: Infinity points are normalized to (0, 0, true) before dispatch to ecc.pil.

### 2.4 Error Event Emission

```cpp
// simulation/gadgets/ecc.cpp:160-171
} catch (const InternalEccException& e) {
    EmbeddedCurvePoint res = EmbeddedCurvePoint(0, 0, false);
    add_memory_events.emit({ .execution_clk = execution_clk,
                             .space_id = space_id,
                             .p = p,
                             .q = q,
                             .result = res,  // Default (0,0,false)
                             .dst_address = dst_address });
    throw EccException("Add failed: " + std::string(e.what()));
}
```

**Verified**: Error events are always emitted even on failure (for trace generation).

---

## 3. Trace Generation Analysis

### 3.1 Curve Equation Verification

```cpp
// tracegen/ecc_trace.cpp:51-60
FF compute_curve_eqn_diff(const EmbeddedCurvePoint& p)
{
    if (p.on_curve()) {
        return FF::zero();
    }
    const FF y2 = p.y() * p.y();
    const FF x3 = p.x() * p.x() * p.x();
    return y2 - (x3 - FF(17));  // Y^2 - (X^3 - 17)
}
```

**Verified**: Matches Grumpkin curve equation. Returns 0 for valid points, non-zero for invalid.

### 3.2 On-Curve Error Inverse Computation

```cpp
// tracegen/ecc_trace.cpp:290-296
bool p_is_on_curve = event.p.on_curve();
FF p_is_on_curve_eqn = compute_curve_eqn_diff(event.p);
FF p_is_on_curve_eqn_inv = p_is_on_curve ? FF::zero() : p_is_on_curve_eqn.invert();

bool q_is_on_curve = event.q.on_curve();
FF q_is_on_curve_eqn = compute_curve_eqn_diff(event.q);
FF q_is_on_curve_eqn_inv = q_is_on_curve ? FF::zero() : q_is_on_curve_eqn.invert();
```

**Verified**:
- When on curve: eqn=0, inv=0 (satisfies zero-check constraint)
- When not on curve: eqn≠0, inv=1/eqn (satisfies zero-check with error flag)

### 3.3 Normalized Point Handling

```cpp
// tracegen/ecc_trace.cpp:300-302
EmbeddedCurvePoint p_n = event.p.is_infinity() ? EmbeddedCurvePoint::infinity() : event.p;
EmbeddedCurvePoint q_n = event.q.is_infinity() ? EmbeddedCurvePoint::infinity() : event.q;
```

**Verified**: Infinity points remapped to (0,0) for ecc.pil lookup.

### 3.4 Error Flag Consolidation

```cpp
// tracegen/ecc_trace.cpp:298
bool error = dst_out_of_range_err || !p_is_on_curve || !q_is_on_curve;
```

**Matches PIL constraint** (ecc_mem.pil line 165):
```pil
err = 1 - (1 - sel_dst_out_of_range_err) * (1 - sel_p_not_on_curve_err) * (1 - sel_q_not_on_curve_err)
```

---

## 4. PIL Constraint Analysis

### 4.1 Curve Equation Verification (PIL)

```pil
// ecc_mem.pil:147
p_is_on_curve_eqn = sel * (P_Y2 - (P_X3 - 17)) * (1 - p_is_inf)
```

Where `P_X3 = p_x * p_x * p_x` and `P_Y2 = p_y * p_y`.

**Analysis**:
- For non-infinity points: verifies Y^2 = X^3 - 17
- For infinity points: `(1 - p_is_inf) = 0` so equation is skipped (correct)

### 4.2 Zero-Check Pattern (PIL)

```pil
// ecc_mem.pil:151
#[P_ON_CURVE_CHECK]
sel * (p_is_on_curve_eqn * ((1 - sel_p_not_on_curve_err) * (1 - p_is_on_curve_eqn_inv) + p_is_on_curve_eqn_inv) - sel_p_not_on_curve_err) = 0
```

**Verified**: Standard zero-check pattern:
- If `p_is_on_curve_eqn = 0`: forces `sel_p_not_on_curve_err = 0`
- If `p_is_on_curve_eqn ≠ 0`: forces `sel_p_not_on_curve_err = 1`

### 4.3 Infinity Point Remapping (PIL)

```pil
// ecc_mem.pil:180-183
sel_should_exec * (p_x_n - (1 - p_is_inf) * p_x - p_is_inf * ecc.INFINITY_X) = 0
sel_should_exec * (p_y_n - (1 - p_is_inf) * p_y - p_is_inf * ecc.INFINITY_Y) = 0
```

**Verified**: Maps infinity to (0,0) for ecc.pil compatibility.

### 4.4 ECC Dispatch Lookup (PIL)

```pil
// ecc_mem.pil:186
#[INPUT_OUTPUT_ECC_ADD]
sel_should_exec {
    p_x_n, p_y_n, p_is_inf,
    q_x_n, q_y_n, q_is_inf,
    res_x, res_y, res_is_inf
} in ecc.sel { ... };
```

**Uses `in` (lookup)**: Correct - multiple ecc_mem rows may reference same ecc row.

### 4.5 Memory Write Permutations (PIL)

```pil
// ecc_mem.pil:201-223
#[WRITE_MEM_0]
sel_should_exec { ..., dst_addr[0], res_x, 0 }
is memory.sel_ecc_write_0 { ..., memory.address, memory.value, memory.tag };
```

**Uses `is` (permutation)**: Correct for memory operations.

---

## 5. Test Coverage Analysis

### 5.1 Existing Test Cases

| Test | Description | Coverage |
|------|-------------|----------|
| `Add` | Basic point addition | ✓ |
| `ScalarMul` | Scalar multiplication | ✓ |
| `ScalarMulNotOnCurve` | Death test for invalid input | ✓ |
| `AddWithMemory` | Memory-aware add | ✓ |
| `AddNotOnCurve` | Error on invalid point | ✓ |
| `InfinityOnCurve` | INF + Q = Q | ✓ |
| `AddsUpToInfinity` | P + (-P) = INF | ✓ |

### 5.2 Fuzzer Analysis

The fuzzer (`ecc.fuzzer.cpp`) provides comprehensive coverage:

**Mutation Strategies**:
1. Random valid points
2. Random invalid points (not on curve)
3. Point at infinity
4. Swap P and Q
5. Set P = -Q (inverse)
6. Random scalars
7. Mutate memory addresses

**Verified Assertions**:
```cpp
BB_ASSERT(result_point.x() == expected_result.x(), "Result x-coordinate mismatch");
BB_ASSERT(result_point.y() == expected_result.y(), "Result y-coordinate mismatch");
BB_ASSERT(result_point.is_infinity() == expected_result.is_infinity(), "Result infinity flag mismatch");
```

**Relation Checks**:
```cpp
check_relation<ecc_rel>(trace);
check_relation<scalar_mul_rel>(trace);
check_all_interactions<EccTraceBuilder>(trace);
```

---

## 6. Caller Analysis

### 6.1 Execution Dispatch (execution.pil:1050)

```pil
// The output point is written to memory internally inside the ecc_add_mem (ecc_mem.pil) trace
sel_exec_dispatch_ecc_add {
    precomputed.clk, context_id,
    rop[6],                    // dst_addr
    register_0_, register_1_, register_2_,  // p_x, p_y, p_is_inf
    register_3_, register_4_, register_5_,  // q_x, q_y, q_is_inf
    sel_opcode_error
} is ecc_add_mem.sel {
    ecc_add_mem.execution_clk, ecc_add_mem.space_id,
    ecc_add_mem.dst_addr[0],
    ecc_add_mem.p_x, ecc_add_mem.p_y, ecc_add_mem.p_is_inf,
    ecc_add_mem.q_x, ecc_add_mem.q_y, ecc_add_mem.q_is_inf,
    ecc_add_mem.err
};
```

**Verified**:
- Uses `is` (permutation) - correct for dispatch
- Input points read from registers (tag checked in execution)
- Error flag propagates correctly

---

## 7. Soundness Verification

### 7.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Output address overflow | CHECK_DST_ADDR_IN_RANGE + gt lookup | PROTECTED |
| Point P not on curve | P_ON_CURVE_CHECK zero-check | PROTECTED |
| Point Q not on curve | Q_ON_CURVE_CHECK zero-check | PROTECTED |
| Wrong ECC result | INPUT_OUTPUT_ECC_ADD lookup | PROTECTED |
| Ghost memory writes | sel_should_exec = sel * (1 - err) | PROTECTED |
| Infinity bypass | Explicit remapping + curve check bypass | PROTECTED |
| Forge error flag | Zero-check pattern enforces consistency | PROTECTED |

### 7.2 Potential Issue: Tag Check Precondition

The PIL file has a precondition (ecc_mem.pil:44-45):
```
// Precondition: Input tags are verified by execution.pil
//   - p_is_inf and q_is_inf are U1
//   - p_x, p_y, q_x, q_y are FF
```

**Verified in execution.pil**:
- Registers are tag-checked before dispatch
- p_is_inf/q_is_inf come from U1 memory reads

---

## 8. Findings

### No Critical Vulnerabilities Found

The ecc_mem gadget is **SOUND**.

### INFO-1: Excellent Fuzzer Coverage

The fuzzer provides comprehensive testing including:
- Invalid points (not on curve)
- Infinity points
- Inverse points (P + (-P) = INF)
- Memory address mutations

### INFO-2: Single-Row Operation

Unlike sha256_mem or keccak_memory, ecc_mem is a single-row operation, simplifying the constraint structure and reducing attack surface.

---

## 9. Conclusion

**Status**: SOUND

The ecc_mem gadget is **correctly implemented** with:
- Proper on-curve verification via Grumpkin equation
- Safe infinity point handling with remapping
- Address bounds checking via gt lookup
- Integration with ecc.pil for correct addition
- Comprehensive fuzzer coverage

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

| Constraint | Purpose |
|------------|---------|
| P_CURVE_EQN | Compute Y^2 - (X^3 - 17) for P |
| P_ON_CURVE_CHECK | Zero-check for P on curve |
| Q_CURVE_EQN | Compute Y^2 - (X^3 - 17) for Q |
| Q_ON_CURVE_CHECK | Zero-check for Q on curve |
| CHECK_DST_ADDR_IN_RANGE | Verify dst_addr+2 ≤ max |
| CONSOLIDATED_ERR | err = OR of all error flags |
| INFINITY_REMAPPING | Map infinity to (0,0) |
| INPUT_OUTPUT_ECC_ADD | Lookup into ecc.pil |
| WRITE_MEM_0/1/2 | Permutations to memory.pil |
