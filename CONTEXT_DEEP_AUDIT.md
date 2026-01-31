# Deep Security Audit: context.pil & context_stack.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL files: `pil/vm2/context.pil` (914 lines), `pil/vm2/context_stack.pil` (62 lines)
- [x] Located simulation code: `simulation/gadgets/context.cpp` (211 lines), `simulation/gadgets/context_provider.cpp` (122 lines)
- [x] Located trace generation: `tracegen/context_stack_trace.cpp` (66 lines)
- [x] Located tests: `context.test.cpp` (1090 lines), `context_stack.test.cpp` (34 lines)
- [x] Identified dependencies: execution.pil, internal_call.pil, tx.pil, external_call.pil

### Phase 2: Understanding
- [x] Documented gadget purpose
- [x] Listed all witnesses (50+ columns)
- [x] Listed all constraints (60+ constraints)
- [x] Listed all lookups/permutations
- [x] Understood data flow

### Phase 3: Soundness
- [x] Verified each constraint
- [x] Analyzed attack vectors
- [x] Checked lookup/permutation soundness
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
| `pil/vm2/context.pil` | 914 | Context state management (virtual gadget) |
| `pil/vm2/context_stack.pil` | 62 | Context stack storage |
| `simulation/gadgets/context.cpp` | 211 | Context classes (Base, Enqueued, Nested) |
| `simulation/gadgets/context_provider.cpp` | 122 | Context factory |
| `tracegen/context_stack_trace.cpp` | 66 | Context stack trace generation |
| Tests | 1124 | Comprehensive constraint tests |

---

## 2. Gadget Architecture

### 2.1 Purpose

The context gadget manages the execution context state across the AVM2 execution trace. It tracks:

1. **Context Identity**: context_id, parent_id, msg_sender, contract_address
2. **Execution State**: pc, next_pc, bytecode_id, is_static
3. **Gas Accounting**: l2/da gas limits and usage for current and parent contexts
4. **Tree State**: 6 Merkle trees + side effects (logs, L2-to-L1 messages)
5. **Internal Call Stack**: IDs for INTERNAL_CALL/INTERNAL_RETURN operations
6. **Child Context Info**: last_child_id, returndata address/size, success flag

### 2.2 Virtual Gadget Structure

This is a **virtual gadget** within the `execution` namespace - it shares columns with execution.pil:

```pil
namespace execution;
    pol DEFAULT_CTX_ROW = sel - sel_enter_call - sel_exit_call;
```

### 2.3 Row Partitioning

Active rows are partitioned into mutually exclusive cases:

| Case | Selector | Description |
|------|----------|-------------|
| Enter nested call | `sel_enter_call = 1` | CALL/STATICCALL instruction |
| Nested return | `nested_return = 1` | RETURN from nested context |
| Nested failure | `nested_failure = 1` | ERROR/REVERT in nested context |
| Top-level exit | `enqueued_call_end = 1` | End of enqueued call |
| Default | `DEFAULT_CTX_ROW = 1` | Regular instruction, no context change |

This partition is critical for constraint coverage:
```
sel = DEFAULT_CTX_ROW + sel_enter_call + nested_return + nested_failure + enqueued_call_end
```

---

## 3. Context Stack Architecture

### 3.1 Purpose

`context_stack.pil` provides storage for parent context state when entering nested calls.

### 3.2 Minimal Constraints

```pil
namespace context_stack;
    pol commit sel; // @boolean
    sel * (1 - sel) = 0;
```

The context stack has **no other constraints** - all semantics come from:
- **Permutation** `#[CTX_STACK_CALL]`: writes to stack (ensures legitimate entries)
- **Lookups** `#[CTX_STACK_ROLLBACK]` and `#[CTX_STACK_RETURN]`: reads from stack

### 3.3 Security Model

The permutation ensures that **only legitimate context entries exist** in the stack. The lookups then safely read from this constrained set.

---

## 4. Simulation Code Analysis

### 4.1 Context Classes

```cpp
// simulation/gadgets/context.cpp
class BaseContext {
    // Common functionality: get_returndata(), get_last_child_id()
};

class EnqueuedCallContext : public BaseContext {
    // Top-level context from public call request
    std::vector<MemoryValue> calldata;  // Own calldata
};

class NestedContext : public BaseContext {
    // Nested context from CALL/STATICCALL
    ContextInterface& parent_context;   // Parent reference
    uint32_t parent_cd_addr;            // Calldata in parent memory
    uint32_t parent_cd_size;
};
```

### 4.2 Context ID Management

```cpp
// simulation/gadgets/context_provider.cpp:37-39
merkle_db.create_checkpoint(); // Fork DB for nested call
uint32_t context_id = next_context_id++;
BB_ASSERT_LTE(context_id, std::numeric_limits<uint16_t>::max(), "Context ID out of bounds");
```

**Verified**: Context IDs are monotonically increasing, bounded to 16 bits for memory space ID.

### 4.3 Merkle DB Checkpoint

The simulation creates a Merkle DB checkpoint on nested call entry. This enables proper rollback on failure.

---

## 5. Trace Generation Analysis

### 5.1 Context Stack Trace

```cpp
// tracegen/context_stack_trace.cpp:22-62
for (const auto& event : ctx_stack_events) {
    trace.set(row, {
        { C::context_stack_sel, 1 },
        { C::context_stack_context_id, event.id },
        { C::context_stack_parent_id, event.parent_id },
        { C::context_stack_entered_context_id, event.entered_context_id },
        { C::context_stack_next_pc, event.next_pc },
        // ... 25+ more columns for tree state, gas, etc.
    });
    row++;
}
```

**Verified**: All 28 context stack columns are populated from the event.

---

## 6. PIL Constraint Analysis

### 6.1 Context ID Propagation

```pil
// context.pil:216-221
#[CONTEXT_ID_EXT_CALL]
sel_enter_call * (context_id' - next_context_id) = 0;
#[CONTEXT_ID_NESTED_EXIT]
NESTED_EXIT_CALL * (context_id' - parent_id) = 0;
#[CONTEXT_ID_NEXT_DEFAULT_ROW]
DEFAULT_CTX_ROW * (context_id' - context_id) = 0;
```

**Analysis**: Complete coverage - on enter_call, context_id becomes next_context_id; on exit, restored to parent_id; otherwise propagated.

### 6.2 Next Context ID Increment

```pil
// context.pil:206-207
#[INCR_NEXT_CONTEXT_ID]
NOT_LAST_EXEC * (next_context_id' - (next_context_id + sel_first_row_in_context')) = 0;
```

**Analysis**: next_context_id increments only when entering a new context (enqueued or nested).

### 6.3 Parent ID Handling

```pil
// context.pil:234-239
#[PARENT_ID_INIT]
enqueued_call_start * parent_id = 0;
#[PARENT_ID_NEXT_EXT_CALL]
sel_enter_call * (parent_id' - context_id) = 0;
#[PARENT_ID_NEXT_DEFAULT_ROW]
DEFAULT_CTX_ROW * (parent_id' - parent_id) = 0;
```

**Analysis**: Enqueued calls have parent_id = 0; nested calls inherit parent_id from caller's context_id.

### 6.4 has_parent_ctx Zero-Check

```pil
// context.pil:134-137
has_parent_ctx * (1 - has_parent_ctx) = 0;
pol commit is_parent_id_inv;
parent_id * ((1 - has_parent_ctx) * (1 - is_parent_id_inv) + is_parent_id_inv) - has_parent_ctx = 0;
```

**Analysis**: Standard zero-check pattern ensuring `has_parent_ctx = 1` iff `parent_id != 0`.

### 6.5 Static Context Propagation

```pil
// context.pil:333-339
#[IS_STATIC_IF_STATIC_CALL]
sel_enter_call * (1 - is_static) * (is_static' - sel_execute_static_call) = 0;
#[IS_STATIC_IF_CALL_FROM_STATIC_CONTEXT]
sel_enter_call * is_static * (is_static' - 1) = 0;
#[IS_STATIC_NEXT_ROW_DEFAULT]
DEFAULT_CTX_ROW * (is_static' - is_static) = 0;
```

**Analysis**:
- From non-static context: STATICCALL → static, CALL → non-static
- From static context: Any call → static (cannot escape)
- Default: propagate unchanged

### 6.6 Gas Tracking

```pil
// context.pil:840-852
#[L2_GAS_USED_ZERO_AFTER_CALL]
sel_enter_call * prev_l2_gas_used' = 0;
#[L2_GAS_USED_INGEST_AFTER_EXIT]
NESTED_EXIT_CALL * (parent_l2_gas_used + l2_gas_used - prev_l2_gas_used') = 0;
#[L2_GAS_USED_DEFAULT_ROW]
DEFAULT_CTX_ROW * (l2_gas_used - prev_l2_gas_used') = 0;
```

**Analysis**:
- On enter_call: gas used resets to 0
- On exit: parent gas + child gas = next prev_gas_used
- Default: current gas becomes next prev_gas_used

### 6.7 Tree State Continuity

```pil
// context.pil:877-902
pol NOT_LAST_NOT_FAILURE_NOT_ENQ_END = sel - nested_failure - enqueued_call_end;

#[NOTE_HASH_TREE_ROOT_CONTINUITY]
NOT_LAST_NOT_FAILURE_NOT_ENQ_END * (note_hash_tree_root - prev_note_hash_tree_root') = 0;
// ... similar for 11 other tree/side-effect columns
```

**Analysis**: Tree state continuity is enforced for:
- Default rows (no context change)
- Enter call (sel_enter_call=1): nested context inherits parent's tree state
- Nested return (nested_return=1): parent adopts child's tree state

NOT enforced for:
- Nested failure: restored via `#[CTX_STACK_ROLLBACK]` lookup
- Enqueued call end: next row initialized via `#[DISPATCH_EXEC_START]`

### 6.8 Context Stack Operations

#### Push (Permutation)

```pil
// context.pil:635-698
#[CTX_STACK_CALL]
sel_enter_call {
    next_context_id,
    context_id, parent_id, next_pc, msg_sender, contract_address, bytecode_id, is_static,
    parent_calldata_addr, parent_calldata_size,
    parent_l2_gas_limit, parent_da_gas_limit, parent_l2_gas_used, parent_da_gas_used,
    internal_call_id, internal_call_return_id, next_internal_call_id,
    note_hash_tree_root, note_hash_tree_size, num_note_hashes_emitted,
    nullifier_tree_root, nullifier_tree_size, num_nullifiers_emitted,
    public_data_tree_root, public_data_tree_size,
    written_public_data_slots_tree_root, written_public_data_slots_tree_size,
    num_unencrypted_log_fields, num_l2_to_l1_messages
} is // PERMUTATION - crucial for security
context_stack.sel { ... };
```

**Uses `is` (permutation)**: Critical for preventing malicious stack entries.

#### Pop on Rollback (Lookup)

```pil
// context.pil:704-767
#[CTX_STACK_ROLLBACK]
nested_failure {
    context_id,
    context_id', parent_id', pc', msg_sender', contract_address', bytecode_id', is_static',
    parent_calldata_addr', parent_calldata_size',
    parent_l2_gas_limit', parent_da_gas_limit', parent_l2_gas_used', parent_da_gas_used',
    internal_call_id', internal_call_return_id', next_internal_call_id',
    // Revert trees and side effects
    prev_note_hash_tree_root', prev_note_hash_tree_size', prev_num_note_hashes_emitted',
    // ... all tree state
} in // LOOKUP - fine for read operation
context_stack.sel { ... };
```

**Uses `in` (lookup)**: Appropriate for read-only pop operation.

#### Pop on Return (Lookup)

```pil
// context.pil:774-812
#[CTX_STACK_RETURN]
nested_return {
    context_id,
    context_id', parent_id', pc', msg_sender', contract_address', bytecode_id', is_static',
    // ... context state (NO tree state - adopted from child)
} in
context_stack.sel { ... };
```

**Key Difference**: `#[CTX_STACK_RETURN]` does NOT restore tree state because successful nested call's effects should persist.

---

## 7. Soundness Verification

### 7.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Forge context_id | CONTEXT_ID_* constraints | PROTECTED |
| Escape static context | IS_STATIC_IF_CALL_FROM_STATIC_CONTEXT | PROTECTED |
| Manipulate parent_id | PARENT_ID_* constraints + permutation | PROTECTED |
| Inject fake stack entries | CTX_STACK_CALL permutation | PROTECTED |
| Read wrong stack entry | Lookup keyed by entered_context_id | PROTECTED |
| Manipulate tree state on enter | *_CONTINUITY constraints | PROTECTED |
| Skip rollback on failure | CTX_STACK_ROLLBACK enforced on nested_failure | PROTECTED |
| Gas accounting manipulation | Gas propagation constraints | PROTECTED |
| Bytecode ID manipulation | BYTECODE_ID_NEXT_ROW | PROTECTED |

### 7.2 Critical Security Properties

#### 7.2.1 Static Context Cannot Be Escaped

From PIL comments and constraints:
```
An external call from a static context always creates a nested static context.
```

Test coverage confirms:
```cpp
// context.test.cpp:780-812
TEST(ContextConstrainingTest, IsStaticCallFromStaticContext)
{
    // Static context making any call - must remain static
    trace.set(C::execution_is_static, 2, 0);
    EXPECT_THROW_WITH_MESSAGE(check_relation<context>(trace, context::SR_IS_STATIC_IF_CALL_FROM_STATIC_CONTEXT),
                              "IS_STATIC_IF_CALL_FROM_STATIC_CONTEXT");
}
```

#### 7.2.2 Tree State Inheritance on Enter Call

Previously a vulnerability - now fixed. Test confirms:
```cpp
// context.test.cpp:855-937
TEST(ContextConstrainingTest, NegativeTreeStateOnEnterCall)
{
    // ATTACK ATTEMPT: Set arbitrary tree state on nested context entry
    { C::execution_prev_note_hash_tree_root, 999999 },  // Should be 100
    // ...
    EXPECT_THROW_WITH_MESSAGE(check_relation<context>(trace, context::SR_NOTE_HASH_TREE_ROOT_CONTINUITY),
                              "NOTE_HASH_TREE_ROOT_CONTINUITY");
}
```

#### 7.2.3 Permutation vs Lookup Choice

- **CTX_STACK_CALL uses `is` (permutation)**: Ensures 1:1 correspondence between caller context and stack entry
- **CTX_STACK_ROLLBACK/RETURN use `in` (lookup)**: Allows reading without removing (not every context is rolled back)

This is correct - a permutation for write prevents malicious insertions, while lookups for read allow multiple accesses.

### 7.3 Gas Accounting Verification

The gas accounting across nested calls is correctly tracked:

1. On enter_call: `prev_gas_used' = 0` (fresh context starts with 0)
2. On exit: `prev_gas_used' = parent_gas_used + gas_used` (accumulate)
3. On error: `l2_gas_used = l2_gas_limit - total_gas_l2` (consume all remaining)

```pil
// context.pil:823-825
pol SEL_CONSUMED_ALL_GAS = sel_error;
(l2_gas_limit - total_gas_l2) * SEL_CONSUMED_ALL_GAS + total_gas_l2 - l2_gas_used = 0;
```

---

## 8. Test Coverage Analysis

### 8.1 Test Summary

| Test | Lines | Coverage |
|------|-------|----------|
| ContextSwitchingCallReturn | 100+ | Full call/return flow with context stack |
| ContextSwitchingExceptionalHalt | 100+ | Error handling with rollback |
| GasNextRow | 100+ | Gas limit propagation |
| GasUsedContinuity | 80+ | Gas used accounting |
| TreeStateContinuity | 100+ | All 12 tree columns |
| SideEffectStateContinuity | 30+ | Logs and L2-to-L1 messages |
| BytecodeIdPropagation | 30+ | Bytecode ID stability |
| IsStatic* (4 tests) | 130+ | Static context propagation |
| NegativeTreeStateOnEnterCall | 80+ | Tree manipulation prevention |
| ContextIdPropagation | 80+ | Context ID lifecycle |

### 8.2 Negative Test Coverage

Excellent coverage with explicit negative tests:
- Wrong gas limits after return
- Wrong gas used after nested call
- Tree state manipulation attempts
- Static flag escape attempts
- Context ID manipulation

---

## 9. Findings

### No Critical Vulnerabilities Found

The context gadget is **SOUND**.

### INFO-1: Complex Virtual Gadget

With 914 lines and 50+ columns, this is one of the most complex gadgets. The partitioning into DEFAULT_CTX_ROW, sel_enter_call, nested_return, nested_failure, and enqueued_call_end is well-designed and provides complete coverage.

### INFO-2: Permutation Security for Stack Push

The use of permutation (`is`) for CTX_STACK_CALL is critical - it prevents malicious prover from inserting fake context entries. This is correctly documented:

```pil
} is // Crucial to be a permutation to prevent malicious insertions
context_stack.sel { ... };
```

### INFO-3: Tree State Rollback vs Adoption

The asymmetric handling of tree state between:
- **nested_failure**: Restores tree state via CTX_STACK_ROLLBACK
- **nested_return**: Adopts child's tree state (no restore)

This is correct semantics - failed calls should not affect state, successful calls should persist changes.

### INFO-4: L1-to-L2 Tree Immutability

```pil
// context.pil:912-913
#[L1_L2_TREE_ROOT_CONTINUITY]
NOT_LAST_EXEC * (l1_l2_tree_root - l1_l2_tree_root') = 0;
```

The L1-to-L2 message tree is immutable during execution - this is correct as it represents external messages that cannot be modified by the AVM.

### INFO-5: Context ID Bounds

```cpp
// context_provider.cpp:38-39
BB_ASSERT_LTE(context_id, std::numeric_limits<uint16_t>::max(), "Context ID out of bounds");
```

Context IDs are bounded to 16 bits for memory space ID compatibility.

---

## 10. Conclusion

**Status**: SOUND

The context.pil and context_stack.pil gadgets are **correctly implemented** with:

- Proper context ID lifecycle management
- Secure context stack via permutation (write) and lookup (read)
- Complete tree state continuity constraints
- Correct static context propagation (cannot escape)
- Sound gas accounting across nested calls
- Appropriate rollback semantics for failed calls
- Comprehensive test coverage including negative tests

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

| Constraint | Purpose |
|------------|---------|
| CONTEXT_ID_* | Context ID propagation on call/return/default |
| PARENT_ID_* | Parent ID initialization and propagation |
| has_parent_ctx | Zero-check for parent_id |
| IS_STATIC_* | Static flag propagation rules |
| *_GAS_LIMIT_* | Gas limit store/restore on call/exit |
| *_GAS_USED_* | Gas used accounting across calls |
| *_CONTINUITY | Tree and side effect state propagation |
| CTX_STACK_CALL | Permutation to push context (security critical) |
| CTX_STACK_ROLLBACK | Lookup to restore on failure |
| CTX_STACK_RETURN | Lookup to restore on success (partial) |

## Appendix: Context Lifecycle

```
Enqueued Call Start (parent_id = 0)
    │
    ├─ [DEFAULT_CTX_ROW] Execute instructions...
    │
    ├─ [sel_enter_call] CALL/STATICCALL
    │       │
    │       └─ Push to context_stack (permutation)
    │       └─ context_id' = next_context_id
    │       └─ parent_id' = context_id
    │       └─ Tree state inherited
    │
    │   Nested Context (parent_id != 0)
    │       │
    │       ├─ [DEFAULT_CTX_ROW] Execute instructions...
    │       │
    │       ├─ [nested_return] RETURN from nested
    │       │       │
    │       │       └─ Pop context_stack (lookup)
    │       │       └─ context_id' = parent_id
    │       │       └─ Tree state ADOPTED from child
    │       │
    │       └─ [nested_failure] ERROR/REVERT in nested
    │               │
    │               └─ Pop context_stack (lookup)
    │               └─ context_id' = parent_id
    │               └─ Tree state RESTORED from stack
    │
    └─ [enqueued_call_end] Return to tx.pil
```
