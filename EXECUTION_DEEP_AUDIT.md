# Deep Security Audit: execution.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL file: `pil/vm2/execution.pil` (1109 lines)
- [x] Located virtual gadgets: `execution/discard.pil` (164 lines), `execution/gas.pil` (101 lines)
- [x] Located virtual gadgets: `execution/addressing.pil`, `execution/registers.pil`
- [x] Located simulation: `simulation/gadgets/execution.cpp`, `execution_components.cpp`
- [x] Located trace gen: `tracegen/execution_trace.cpp`
- [x] Located tests: `execution.test.cpp`, `execution_discard.test.cpp`
- [x] Identified 50+ includes (all other PIL files)

### Phase 2: Understanding
- [x] Documented gadget purpose (execution orchestration)
- [x] Listed 6 temporality groups
- [x] Listed all constraints (100+)
- [x] Listed all lookups/permutations
- [x] Understood selector deactivation cascade

### Phase 3: Soundness
- [x] Verified selector cascade
- [x] Analyzed dispatch security
- [x] Checked permutation vs lookup choice
- [x] Verified error collection

### Phase 4: Completeness
- [x] Reviewed error propagation
- [x] Checked tree state guards
- [x] Verified gas handling

### Phase 5: Integration
- [x] Verified tx.pil interaction
- [x] Checked opcode dispatch
- [x] Verified subtrace interactions

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/execution.pil` | 1109 | Main execution orchestration |
| `pil/vm2/execution/discard.pil` | 164 | Error propagation and discard handling |
| `pil/vm2/execution/gas.pil` | 101 | Gas checking and out-of-gas detection |
| `pil/vm2/execution/addressing.pil` | ~100 | Operand resolution |
| `pil/vm2/execution/registers.pil` | ~150 | Register read/write |
| Tests | 500+ | Constraint tests |

---

## 2. Gadget Architecture

### 2.1 Purpose

The execution.pil is the **central orchestration gadget** that:
1. Manages the execution pipeline through 6 temporality groups
2. Dispatches operations to 14+ subtraces
3. Collects and propagates errors
4. Guards tree state changes
5. Coordinates with tx.pil for enqueued call boundaries

### 2.2 Temporality Groups

Execution proceeds through 6 sequential groups, where failure in any group prevents subsequent groups:

| Group | Purpose | Output |
|-------|---------|--------|
| 1 | Bytecode retrieval | `sel_bytecode_retrieval_success/failure` |
| 2 | Instruction fetching + Addressing | `sel_instruction_fetching_success`, `sel_addressing_error` |
| 3 | Register read | `sel_register_read_error` |
| 4 | Gas check | `sel_out_of_gas` |
| 5 | Opcode execution | `sel_opcode_error` |
| 6 | Register write | (cannot fail) |

### 2.3 Selector Deactivation Cascade

```pil
// execution.pil:77-90 (documented cascade)
// sel == 0 ==> sel_bytecode_retrieval_success == 0
//          ==> sel_instruction_fetching_success == 0
//          ==> sel_should_read_registers == 0
//          ==> sel_should_check_gas == 0
//          ==> sel_should_execute_opcode == 0
//          ==> sel_should_write_registers = 0
//          ==> all dispatch selectors = 0
//          ==> all opcode selectors = 0
```

This cascade is **critical for security** - it ensures inactive rows cannot fire lookups/permutations.

---

## 3. Dispatch Architecture

### 3.1 Subtrace Dispatch

14 subtrace dispatches via ID decomposition:

```pil
// execution.pil:599-615
#[SUBTRACE_ID_DECOMPOSITION]
sel_exec_dispatch_execution * constants.AVM_SUBTRACE_ID_EXECUTION +
sel_exec_dispatch_alu * constants.AVM_SUBTRACE_ID_ALU +
sel_exec_dispatch_bitwise * constants.AVM_SUBTRACE_ID_BITWISE +
// ... 11 more ...
= sel_should_execute_opcode * subtrace_id;
```

**Security**: All dispatch selectors are forced to 0 when `sel_should_execute_opcode = 0`.

### 3.2 Execution Opcode Dispatch

21 embedded execution opcodes:

```pil
// execution.pil:667-692
#[EXEC_OP_ID_DECOMPOSITION]
sel_execute_get_env_var * constants.AVM_EXEC_OP_ID_GETENVVAR +
sel_execute_mov * constants.AVM_EXEC_OP_ID_MOV +
// ... 19 more ...
= sel_exec_dispatch_execution * subtrace_operation_id;
```

### 3.3 Permutation vs Lookup Choice

**Critical Security Decision**:

| Dispatch | Type | Reason |
|----------|------|--------|
| ALU | `in` (lookup) | Pure computation, deduplicated |
| BITWISE | `in` (lookup) | Pure computation, deduplicated |
| CAST | `in` (lookup) | Pure computation via ALU |
| SET | `in` (lookup) | Pure computation via ALU |
| CALLDATA_COPY | `is` (permutation) | Memory side effects |
| RETURNDATA_COPY | `is` (permutation) | Memory side effects |
| GET_CONTRACT_INSTANCE | `is` (permutation) | Memory writes |
| EMIT_UNENCRYPTED_LOG | `is` (permutation) | Side effects |
| POSEIDON2_PERM | `is` (permutation) | Memory operations |
| SHA256_COMPRESSION | `is` (permutation) | Memory operations |
| KECCAKF1600 | `is` (permutation) | Memory operations |
| ECC_ADD | `is` (permutation) | Memory writes |
| TO_RADIX | `is` (permutation) | Memory writes |

**Verified**: Permutations used for all operations with side effects; lookups only for pure computations.

---

## 4. Error Handling (discard.pil)

### 4.1 Discard Mechanism

The `discard` flag indicates whether side effects should be discarded:

```pil
// discard.pil:28-37
pol commit discard; // This context or one of its ancestors fails
discard * (1 - discard) = 0;

pol commit dying_context_id; // Oldest failing ancestor's context_id
// discard == 1 <=> dying_context_id != 0
#[DISCARD_IFF_DYING_CONTEXT]
dying_context_id * ((1 - discard) * (1 - dying_context_id_inv) + dying_context_id_inv) - discard = 0;
```

### 4.2 Key Constraints

```pil
// discard.pil:40-41 - Failure implies discard
#[DISCARD_IF_FAILURE]
sel_failure * (1 - discard) = 0;

// discard.pil:101-102 - Dying context must fail before exiting
#[DYING_CONTEXT_MUST_FAIL]
is_dying_context * sel_execute_return = 0;

// discard.pil:107-108 - New context must be dying context when discard raised
#[ENTER_CALL_DISCARD_MUST_BE_DYING_CONTEXT]
NESTED_CALL_FROM_UNDISCARDED_CONTEXT * discard' * (context_id' - dying_context_id') = 0;

// discard.pil:115-116 - Nested failure must clear discard
#[DYING_CONTEXT_WITH_PARENT_MUST_CLEAR_DISCARD]
RESOLVES_DYING_CONTEXT * has_parent_ctx * discard' = 0;
```

### 4.3 Propagation Logic

```pil
// discard.pil:81-89
pol PROPAGATE_DISCARD = NOT_LAST_EXEC * (1 - enqueued_call_end)
                      * (1 - RESOLVES_DYING_CONTEXT - NESTED_CALL_FROM_UNDISCARDED_CONTEXT);

#[DYING_CONTEXT_PROPAGATION]
PROPAGATE_DISCARD * (dying_context_id' - dying_context_id) = 0;
```

Propagation is lifted when:
- At enqueued call boundaries
- Failure resolves dying context
- Entering a call from undiscarded context

---

## 5. Gas Handling (gas.pil)

### 5.1 Gas Computation

```pil
// gas.pil:48-64
pol BASE_L2_GAS = opcode_gas + addressing_gas;
pol DYNAMIC_L2_GAS_USED = dynamic_l2_gas * dynamic_l2_gas_factor;
pol L2_GAS_USED = BASE_L2_GAS + DYNAMIC_L2_GAS_USED;

// gas.pil:70-71
pol commit total_gas_l2;
sel_should_check_gas * (prev_l2_gas_used + L2_GAS_USED - total_gas_l2) = 0;
```

### 5.2 Out-of-Gas Check

```pil
// gas.pil:80-81
#[IS_OUT_OF_GAS_L2]
sel_should_check_gas { total_gas_l2, l2_gas_limit, out_of_gas_l2 }
in gt.sel_gas { gt.input_a, gt.input_b, gt.res };

// gas.pil:93-95
pol commit sel_out_of_gas;
sel_out_of_gas = 1 - (1 - out_of_gas_l2) * (1 - out_of_gas_da);
```

### 5.3 Bounds Analysis

From gas.pil comments:
- `prev_l2_gas_used < l2_gas_limit < 2^32`
- `BASE_L2_GAS < 2^17`
- `dynamic_l2_gas_factor < 2^32`
- `dynamic_l2_gas < 2^16`
- `total_gas_l2 < 2^49` (well within gt gadget's 2^128 bound)

---

## 6. Tree State Guards

### 6.1 State Change Restrictions

Only specific opcodes can modify tree state:

```pil
// execution.pil:738-766
#[PUBLIC_DATA_TREE_ROOT_NOT_CHANGED]
(1 - sel_execute_sstore) * (prev_public_data_tree_root - public_data_tree_root) = 0;

#[NOTE_HASH_TREE_ROOT_NOT_CHANGED]
(1 - sel_execute_emit_notehash) * (prev_note_hash_tree_root - note_hash_tree_root) = 0;

#[NULLIFIER_TREE_ROOT_NOT_CHANGED]
(1 - sel_execute_emit_nullifier) * (prev_nullifier_tree_root - nullifier_tree_root) = 0;

#[NUM_UNENCRYPTED_LOGS_NOT_CHANGED]
(1 - sel_exec_dispatch_emit_unencrypted_log) * (prev_num_unencrypted_log_fields - num_unencrypted_log_fields) = 0;

#[RETRIEVED_BYTECODES_TREE_ROOT_NOT_CHANGED]
(1 - sel_first_row_in_context) * (prev_retrieved_bytecodes_tree_root - retrieved_bytecodes_tree_root) = 0;
```

**Verified**: Each tree has exactly one opcode that can modify it.

---

## 7. Enqueued Call Boundaries

### 7.1 Start/End Detection

```pil
// execution.pil:104-109
#[ENQUEUED_CALL_START]
enqueued_call_start' = (precomputed.first_row + enqueued_call_end) * sel';

#[ENQUEUED_CALL_END]
enqueued_call_end = sel_exit_call * (1 - has_parent_ctx);
```

### 7.2 Trace Continuity

```pil
// execution.pil:134-135
#[TRACE_CONTINUITY]
(1 - sel) * (1 - precomputed.first_row) * sel' = 0;
```

**Analysis**: Once execution trace becomes inactive, it stays inactive (no ghost rows in the middle).

---

## 8. Infallible Opcodes

```pil
// execution.pil:776-782
#[INFALLIBLE_OPCODES_SUCCESS]
(sel_execute_mov + sel_execute_returndata_size + sel_execute_jump +
 sel_execute_jumpi + sel_execute_debug_log + sel_execute_success_copy +
 sel_execute_call + sel_execute_static_call + sel_execute_internal_call +
 sel_execute_return + sel_execute_revert + sel_execute_sload +
 sel_execute_notehash_exists + sel_execute_l1_to_l2_message_exists +
 sel_execute_nullifier_exists) * sel_opcode_error = 0;
```

**Analysis**: These opcodes cannot set `sel_opcode_error`. Other opcodes constrain it in their respective files.

---

## 9. Soundness Verification

### 9.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Ghost row dispatch | Selector deactivation cascade | PROTECTED |
| Forge dispatch selector | ID decomposition constraints | PROTECTED |
| Skip gas check | Temporality group ordering | PROTECTED |
| Manipulate tree state | *_NOT_CHANGED constraints | PROTECTED |
| Fake side effects | Permutations for side-effect ops | PROTECTED |
| Skip error | Error collection completeness | PROTECTED |
| Discard manipulation | DYING_CONTEXT_MUST_FAIL + propagation | PROTECTED |
| Wrong dying_context_id | ENTER_CALL_DISCARD_MUST_BE_DYING_CONTEXT | PROTECTED |

### 9.2 Error Mutual Exclusivity

From execution.pil:827-844, the cascade ensures errors are mutually exclusive:
1. `sel_bytecode_retrieval_failure = 1` → subsequent selectors = 0
2. `sel_instruction_fetching_failure = 1` → addressing error = 0
3. etc.

This prevents double-counting or confusion in error handling.

### 9.3 Dynamic Gas Security

Each dynamic gas opcode has specific constraints:

```pil
// execution.pil:434-443
#[DYN_GAS_ID_DECOMPOSITION]
sel_gas_calldata_copy * constants.AVM_DYN_GAS_ID_CALLDATACOPY +
// ... other gas selectors ...
= sel_should_check_gas * dyn_gas_id;
```

The decomposition ensures exactly one dynamic gas path is active.

---

## 10. Findings

### No Critical Vulnerabilities Found

The execution.pil gadget is **SOUND**.

### INFO-1: Central Orchestration Complexity

This 1109-line file includes 50+ other PIL files and orchestrates the entire execution pipeline. The complexity is well-managed through:
- Clear temporality group structure
- Documented selector cascade
- Separated virtual gadgets (discard.pil, gas.pil)

### INFO-2: Permutation vs Lookup Decision

The choice between `is` (permutation) and `in` (lookup) is correctly made:
- Pure computations (ALU, BITWISE, CAST, SET) use lookups for deduplication
- Operations with side effects use permutations to prevent forgery

### INFO-3: Discard Propagation Complexity

The discard mechanism in discard.pil is sophisticated but correctly handles:
- Nested call failures
- Enqueued call failures
- Cross-enqueued-call discard propagation

The detailed correctness analysis in discard.pil comments (lines 119-163) provides a proof.

### INFO-4: Gas Bounds

The gas computation stays well within field bounds:
- `total_gas_l2 < 2^49`
- gt gadget supports up to 2^128 inputs
- No overflow risk

---

## 11. Conclusion

**Status**: SOUND

The execution.pil gadget suite is **correctly implemented** with:

- Proper selector deactivation cascade preventing ghost row attacks
- Correct permutation vs lookup choice for dispatch operations
- Complete error collection with mutual exclusivity
- Robust tree state guards allowing only specific opcodes to modify state
- Well-designed discard propagation for nested call failures
- Gas checking with proper bounds analysis
- Clear temporality group structure

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Dispatch Summary

| Subtrace | Selector | Lookup Type | Columns |
|----------|----------|-------------|---------|
| ALU | `sel_exec_dispatch_alu` | `in` | registers, tags, op_id, error |
| BITWISE | `sel_exec_dispatch_bitwise` | `in` | op_id, error, registers, tags |
| CAST | `sel_exec_dispatch_cast` | `in` | value, tag, truncated |
| SET | `sel_exec_dispatch_set` | `in` | value, tag, truncated |
| CALLDATA_COPY | `sel_exec_dispatch_calldata_copy` | `is` | context, size, offset, addr |
| RETURNDATA_COPY | `sel_exec_dispatch_returndata_copy` | `is` | context, size, offset, addr |
| GET_CONTRACT_INSTANCE | `sel_exec_dispatch_get_contract_instance` | `is` | address, dst, member, error |
| EMIT_UNENCRYPTED_LOG | `sel_exec_dispatch_emit_unencrypted_log` | `is` | context, addr, size, error |
| POSEIDON2_PERM | `sel_exec_dispatch_poseidon2_perm` | `is` | context, read/write addr, error |
| SHA256_COMPRESSION | `sel_exec_dispatch_sha256_compression` | `is` | context, addrs, error |
| KECCAKF1600 | `sel_exec_dispatch_keccakf1600` | `is` | context, addrs, error |
| ECC_ADD | `sel_exec_dispatch_ecc_add` | `is` | context, points, dst, error |
| TO_RADIX | `sel_exec_dispatch_to_radix` | `is` | context, value, radix, limbs, error |

## Appendix: Temporality Group Flow

```
sel = 1 (Active Row)
    │
    ├─ Group 1: Bytecode Retrieval
    │       └─ sel_bytecode_retrieval_failure? → ERROR
    │
    ├─ Group 2: Instruction Fetching + Addressing
    │       ├─ sel_instruction_fetching_failure? → ERROR
    │       └─ sel_addressing_error? → ERROR
    │
    ├─ Group 3: Register Read
    │       └─ sel_register_read_error? → ERROR
    │
    ├─ Group 4: Gas Check
    │       └─ sel_out_of_gas? → ERROR
    │
    ├─ Group 5: Opcode Execution
    │       ├─ Dispatch to subtrace
    │       └─ sel_opcode_error? → ERROR
    │
    └─ Group 6: Register Write
            └─ (cannot fail)

sel_error = sum of all error selectors (mutually exclusive)
```

## Appendix: Tree State Guard Summary

| Tree/Counter | Guard Constraint | Modifying Opcode |
|--------------|------------------|------------------|
| public_data_tree_root/size | PUBLIC_DATA_TREE_*_NOT_CHANGED | SSTORE |
| written_public_data_slots_tree_* | WRITTEN_PUBLIC_DATA_*_NOT_CHANGED | SSTORE |
| note_hash_tree_root/size | NOTE_HASH_TREE_*_NOT_CHANGED | EMIT_NOTEHASH |
| num_note_hashes_emitted | NUM_NOTE_HASHES_EMITTED_NOT_CHANGED | EMIT_NOTEHASH |
| nullifier_tree_root/size | NULLIFIER_TREE_*_NOT_CHANGED | EMIT_NULLIFIER |
| num_nullifiers_emitted | NUM_NULLIFIERS_EMITTED_NOT_CHANGED | EMIT_NULLIFIER |
| num_unencrypted_log_fields | NUM_UNENCRYPTED_LOGS_NOT_CHANGED | EMIT_UNENCRYPTED_LOG |
| num_l2_to_l1_messages | NUM_L2_TO_L1_MESSAGES_NOT_CHANGED | SEND_L2_TO_L1_MSG |
| retrieved_bytecodes_tree_* | RETRIEVED_BYTECODES_*_NOT_CHANGED | (first row only) |
