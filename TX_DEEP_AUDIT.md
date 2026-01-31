# Deep Security Audit: tx.pil (Transaction Trace)

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL files: `pil/vm2/tx.pil` (748 lines), `tx_context.pil` (493 lines), `tx_discard.pil` (59 lines)
- [x] Located simulation code: `simulation/gadgets/tx_execution.cpp` (698 lines)
- [x] Located trace generation: `tracegen/tx_trace.cpp` (750 lines)
- [x] Located tests: `simulation/gadgets/tx_execution.test.cpp` (455 lines), `tracegen/tx_trace.test.cpp` (360 lines)
- [x] Identified role: Top-level transaction orchestrator (no callers - it IS the top)

### Phase 2: Understanding
- [x] Documented gadget purpose
- [x] Listed all witnesses (~100+ columns)
- [x] Listed all constraints (~80+ constraints)
- [x] Listed all lookups/permutations (30+ interactions)
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
- [x] Verified cross-gadget interactions
- [x] Checked protocol_write vs non_protocol_write separation

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/tx.pil` | 748 | Main transaction trace |
| `pil/vm2/tx_context.pil` | 493 | Tree state management (virtual) |
| `pil/vm2/tx_discard.pil` | 59 | Discard flag management (virtual) |
| `simulation/gadgets/tx_execution.cpp` | 698 | Simulation logic |
| `tracegen/tx_trace.cpp` | 750 | Trace generation |
| `tracegen/lib/phase_spec.cpp` | 108 | Phase specifications |

---

## 2. Gadget Architecture

### 2.1 Purpose

The tx.pil gadget is the **top-level transaction orchestrator** for the AVM circuit. It manages:
- Transaction phase sequencing (12 phases)
- State transitions (tree roots, side effects)
- Revert handling and state restoration
- Fee collection and validation
- Dispatch to execution trace

### 2.2 Transaction Phases

| Phase | Value | Description | Revertible |
|-------|-------|-------------|------------|
| NR_NULLIFIER_INSERTION | 0 | Non-revertible nullifiers | No |
| NR_NOTE_INSERTION | 1 | Non-revertible note hashes | No |
| NR_L2_TO_L1_MESSAGE | 2 | Non-revertible L2→L1 msgs | No |
| SETUP | 3 | Setup enqueued calls | No |
| R_NULLIFIER_INSERTION | 4 | Revertible nullifiers | Yes → TEARDOWN |
| R_NOTE_INSERTION | 5 | Revertible note hashes | Yes → TEARDOWN |
| R_L2_TO_L1_MESSAGE | 6 | Revertible L2→L1 msgs | Yes → TEARDOWN |
| APP_LOGIC | 7 | App logic enqueued calls | Yes → TEARDOWN |
| TEARDOWN | 8 | Teardown enqueued call | Yes → COLLECT_GAS_FEES |
| COLLECT_GAS_FEES | 9 | Fee payment | No |
| TREE_PADDING | 10 | Pad trees to max size | No |
| CLEANUP | 11 | Write final state to PI | No |

### 2.3 Virtual Sub-traces

**tx_context.pil**: Manages tree state continuity and immutability
- Note hash tree (root, size, counter)
- Nullifier tree (root, size, counter)
- Public data tree (root, size)
- L1→L2 message tree (immutable)
- Gas used and limits

**tx_discard.pil**: Manages discard flag for reverting side effects
- `discard` propagates unless revert or end of setup
- `discard` can only be set in revertible phases

---

## 3. Simulation Code Analysis

### 3.1 Phase Execution Order

```cpp
// simulation/gadgets/tx_execution.cpp:62-276
TxExecutionResult TxExecution::simulate(const Tx& tx)
{
    // 1. Non-revertible insertions (can throw, unprovable)
    insert_non_revertibles(tx);

    // 2. Setup phase (can throw, unprovable)
    for (const auto& call : tx.setup_enqueued_calls) {
        // Execute with transaction_fee = 0
    }

    // CREATE CHECKPOINT
    merkle_db.create_checkpoint();
    contract_db.create_checkpoint();

    // 3-7. Revertible phases (catch exceptions, provable)
    try {
        insert_revertibles(tx);
        // App logic calls
    } catch (const TxExecutionException& e) {
        merkle_db.revert_checkpoint();
    }

    // 8. Teardown (catch exceptions, provable)
    try {
        // Execute teardown with actual fee
    } catch (const TxExecutionException& e) {
        merkle_db.revert_checkpoint();
    }

    // 9. Pay fee (can throw if insufficient balance)
    pay_fee(tx.fee_payer, fee, ...);

    // 10. Pad trees
    pad_trees();

    // 11. Cleanup
    cleanup();
}
```

**Verified**: Checkpoint/rollback pattern correctly implements revert semantics.

### 3.2 Fee Payment Validation

```cpp
// simulation/gadgets/tx_execution.cpp:596-604
if (field_gt.ff_gt(fee, fee_payer_balance)) {
    if (skip_fee_enforcement) {
        fee_payer_balance = fee;
    } else {
        throw TxExecutionException("Not enough balance for fee payer");
    }
}
```

**Verified**: Fee validation uses `field_gt` gadget for comparison.

### 3.3 Limit Enforcement

```cpp
// simulation/gadgets/tx_execution.cpp:348-349
if (prev_nullifier_count == MAX_NULLIFIERS_PER_TX) {
    throw TxExecutionException("Maximum number of nullifiers reached");
}
```

**Verified**: All limits (nullifiers, note hashes, L2→L1 messages) are enforced.

---

## 4. Trace Generation Analysis

### 4.1 Phase Event Processing

```cpp
// tracegen/tx_trace.cpp:615-706
for (uint32_t i = 0; i < NUM_PHASES; i++) {
    const auto& phase_events = phase_buckets[i];
    if (phase_events.empty()) {
        continue; // Skip phases with no events (jumped due to revert)
    }

    // Process each event in phase
    for (const auto* tx_phase_event : phase_events) {
        trace.set(row, { { /* columns */ } });
        // ... pattern match on event type
    }
}
```

**Verified**: Phases are processed in order, empty phases are skipped.

### 4.2 Discard Flag Computation

```cpp
// tracegen/tx_trace.cpp:626-634
bool discard = false;
if (is_revertible(phase)) {
    if (is_teardown(phase)) {
        discard = teardown_failure;
    } else {
        discard = teardown_failure || r_insertion_or_app_logic_failure;
    }
}
```

**Verified**: Discard logic matches PIL constraints.

### 4.3 Batch Inversions

```cpp
// tracegen/tx_trace.cpp:709-710
trace.invert_columns({
    { C::tx_remaining_phase_inv, C::tx_remaining_phase_minus_one_inv, C::tx_remaining_side_effects_inv }
});
```

**Verified**: All inverse columns are batch-inverted for zero-check patterns.

---

## 5. PIL Constraint Analysis

### 5.1 Phase Ordering

```pil
// tx.pil - Phase control flow
#[START_PHASE_VALUE_INITIALIZATION]
start_tx * (phase_value - constants.AVM_TX_PHASE_VALUE_START) = 0;

#[INCR_PHASE_VALUE_ON_END]
sel' * (1 - reverted) * end_phase * (phase_value' - (phase_value + 1)) = 0;

#[NO_EARLY_END]
sel * (1 - sel') * (phase_value - constants.AVM_TX_PHASE_VALUE_LAST) = 0;
```

**Analysis**:
- Phase starts at 0
- Phases increment by 1 at end_phase (unless reverted)
- Transaction can only end at phase 11 (CLEANUP)

### 5.2 Revert Handling

```pil
// tx.pil:227-228
#[PHASE_JUMP_ON_REVERT]
reverted * (next_phase_on_revert - phase_value') = 0;
```

```pil
// tx_context.pil:288-320
#[RESTORE_STATE_ON_REVERT]
reverted {
    setup_phase_value,  // Must be end of SETUP
    reverted,           // Must be end_phase
    prev_note_hash_tree_root',
    // ... all state columns
} in tx.sel {
    phase_value,
    end_phase,
    next_note_hash_tree_root,
    // ... all state columns
};
```

**Analysis**:
- On revert, jump to `next_phase_on_revert` (TEARDOWN or COLLECT_GAS_FEES)
- State must be restored to end-of-SETUP values via lookup
- This prevents any state changes from revertible phases from persisting

### 5.3 Discard Flag Security

```pil
// tx_discard.pil
#[CAN_ONLY_DISCARD_IN_REVERTIBLE_PHASES]
discard * (1 - is_revertible) = 0;

#[REVERTED_MUST_DISCARD]
reverted * (1 - discard) = 0;

#[DISCARD_PROPAGATION]
sel * PROPAGATE_DISCARD * (discard' - discard) = 0;
```

**Analysis**:
- `discard` can only be 1 if `is_revertible = 1`
- If `reverted = 1`, then `discard = 1`
- Discard propagates by default, lifted only at setup end or revert

**Ghost Attack Prevention** (from comments):
> If a malicious prover toggles `discard == 1` and `reverted == 0`, then
> `discard == 1` propagates to the next row as long as there is no revert.
> Then, it will reach the `collect_gas_fees` row, where `discard == 1` contradicts that
> `is_revertible == 0`.

### 5.4 Fee Payment

```pil
// tx.pil:689-691
#[BALANCE_VALIDATION]
is_collect_fee { fee, fee_payer_balance, precomputed.zero }
in ff_gt.sel_gt { ff_gt.a, ff_gt.b, ff_gt.result };
```

**Uses `in` (lookup)**: Correct - ff_gt may deduplicate.

```pil
// tx.pil:699-720
#[BALANCE_UPDATE]
is_collect_fee {
    fee_payer_new_balance,
    fee_juice_contract_address,
    fee_juice_balance_slot,
    discard,
    prev_public_data_tree_root,
    next_public_data_tree_root,
    ...
} is public_data_check.protocol_write { ... };
```

**Uses `is` (permutation)**: Correct - fee payment is unique operation.

---

## 6. Test Coverage Analysis

### 6.1 Simulation Tests

| Test | Description | Coverage |
|------|-------------|----------|
| `simulateTx` | Full transaction simulation | ✓ |
| `NoteHashLimitReached` | Revert on max note hashes | ✓ |
| `NullifierLimitReached` | Revert on max nullifiers | ✓ |
| `L2ToL1MessageLimitReached` | Revert on max messages | ✓ |

### 6.2 Trace Generation Tests

| Test | Description | Coverage |
|------|-------------|----------|
| `EnqueuedCallEvent` | SETUP phase with call | ✓ |
| `CollectFeeEvent` | Fee collection | ✓ |
| `BasicFirstPaddedRow` | Empty phase (padded) | ✓ |
| `PadTreesEvent` | Tree padding | ✓ |
| `CleanupEvent` | Cleanup phase | ✓ |
| `CleanupRevertedEvent` | Revert with cleanup | ✓ |

### 6.3 Coverage Gaps

| Test Case | Status |
|-----------|--------|
| Multi-phase sequence | NOT COVERED |
| APP_LOGIC with multiple calls | NOT COVERED |
| TEARDOWN phase | NOT COVERED |
| State restoration after revert | NOT COVERED |
| Fee insufficient error | NOT COVERED |

**Recommendation**: Add comprehensive multi-phase integration tests.

---

## 7. Cross-Gadget Interactions

### 7.1 Execution Dispatch

```pil
// tx.pil:319-381, 393-447
#[DISPATCH_EXEC_START]
should_process_call_request { ... } is execution.enqueued_call_start { ... };

#[DISPATCH_EXEC_END]
should_process_call_request { ... } is execution.enqueued_call_end { ... };
```

**Uses `is` (permutation)**: Correct for 1-1 call dispatch.

### 7.2 Protocol vs Non-Protocol Writes

```pil
// tx.pil:710 - Fee payment
} is public_data_check.protocol_write { ... };

// sstore.pil:87 - User storage write
} is public_data_check.non_protocol_write { ... };
```

**Analysis**: The separation ensures:
- Fee payments can only happen through tx.pil flow
- User storage writes cannot bypass fee validation

### 7.3 Tree Interactions

| Lookup | Target Gadget | Type |
|--------|---------------|------|
| NOTE_HASH_APPEND | note_hash_tree_check.write | `in` |
| NULLIFIER_APPEND | nullifier_check.write | `in` |
| BALANCE_READ | public_data_check.sel | `in` |
| BALANCE_UPDATE | public_data_check.protocol_write | `is` |
| BALANCE_SLOT_POSEIDON2 | poseidon2_hash.start | `in` |

---

## 8. Soundness Verification

### 8.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Skip phase | Phase increment enforced + NO_EARLY_END | PROTECTED |
| Reorder phases | READ_PHASE_SPEC lookup + counter chain | PROTECTED |
| Forge revert in non-revertible | CAN_ONLY_DISCARD constraint fails | PROTECTED |
| Skip fee payment | COLLECT_GAS_FEES is mandatory one-shot | PROTECTED |
| Insufficient fee | BALANCE_VALIDATION lookup into ff_gt | PROTECTED |
| Forge state after revert | RESTORE_STATE_ON_REVERT lookup | PROTECTED |
| Ghost discard flag | Propagates to non-revertible phase → fail | PROTECTED |
| State manipulation | Immutability + continuity constraints | PROTECTED |

### 8.2 Critical Security Properties

1. **Phase Ordering Integrity**: Phases must traverse 0→11 in order
2. **Revert Semantics**: State correctly restored to end-of-setup
3. **Fee Payment**: Cannot be skipped or forged
4. **Discard Propagation**: Cannot be forged without actual revert
5. **Tree State Chain**: Proper continuity across phases

---

## 9. Findings

### No Critical Vulnerabilities Found

The tx.pil gadget is **SOUND**.

### INFO-1: Complex Constraint Set

With ~80+ constraints across 3 files, the tx.pil system is highly complex. The constraint interactions are well-documented but require careful maintenance.

### INFO-2: Test Coverage Gaps

While unit tests exist, there are no comprehensive multi-phase integration tests that exercise the full transaction lifecycle with reverts.

### INFO-3: Virtual Subtrace Pattern

The use of virtual subtraces (tx_context.pil, tx_discard.pil) that share columns with tx.pil is a powerful but complex pattern. The column references are implicit.

### LOW-1: Limited Trace Test Coverage

Trace generation tests cover individual phases but not multi-phase sequences with state restoration.

---

## 10. Conclusion

**Status**: SOUND

The tx.pil gadget (with tx_context.pil and tx_discard.pil) is **correctly implemented** with:
- Proper phase sequencing and ordering enforcement
- Sound revert handling with state restoration
- Secure fee payment validation
- Ghost attack prevention via discard propagation
- Correct separation of protocol vs non-protocol writes
- Comprehensive integration with tree and execution gadgets

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix A: Key Constraint Summary

| Constraint | File | Purpose |
|------------|------|---------|
| START_PHASE_VALUE_INITIALIZATION | tx.pil | Phase starts at 0 |
| INCR_PHASE_VALUE_ON_END | tx.pil | Phase increments |
| NO_EARLY_END | tx.pil | Can only end at phase 11 |
| READ_PHASE_SPEC | tx.pil | Get phase attributes |
| PHASE_JUMP_ON_REVERT | tx.pil | Jump on revert |
| DISPATCH_EXEC_START/END | tx.pil | Call dispatch |
| NOTE_HASH_APPEND | tx.pil | Note hash insertion |
| NULLIFIER_APPEND | tx.pil | Nullifier insertion |
| BALANCE_VALIDATION | tx.pil | Fee check |
| BALANCE_UPDATE | tx.pil | Fee payment |
| PAD_NOTE_HASH/NULLIFIER_TREE | tx.pil | Tree padding |
| RESTORE_STATE_ON_REVERT | tx_context.pil | State restoration |
| *_CONTINUITY | tx_context.pil | State chaining |
| *_IMMUTABILITY | tx_context.pil | State protection |
| CAN_ONLY_DISCARD_IN_REVERTIBLE | tx_discard.pil | Discard restriction |
| REVERTED_MUST_DISCARD | tx_discard.pil | Revert→discard |
| DISCARD_PROPAGATION | tx_discard.pil | Discard chaining |

## Appendix B: Phase Specification Map

| Phase | is_revertible | next_phase_on_revert |
|-------|---------------|---------------------|
| 0 (NR_NULLIFIER) | false | - |
| 1 (NR_NOTE_HASH) | false | - |
| 2 (NR_L2_TO_L1) | false | - |
| 3 (SETUP) | false | - |
| 4 (R_NULLIFIER) | true | 8 (TEARDOWN) |
| 5 (R_NOTE_HASH) | true | 8 (TEARDOWN) |
| 6 (R_L2_TO_L1) | true | 8 (TEARDOWN) |
| 7 (APP_LOGIC) | true | 8 (TEARDOWN) |
| 8 (TEARDOWN) | true | 9 (COLLECT_GAS_FEES) |
| 9 (COLLECT_GAS_FEES) | false | - |
| 10 (TREE_PADDING) | false | - |
| 11 (CLEANUP) | false | - |
