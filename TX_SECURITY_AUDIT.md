# Security Audit: tx.pil (+ tx_context.pil + tx_discard.pil)

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `tx.pil` gadget is the top-level trace of the AVM circuit, managing 12 transaction phases. Two virtual sub-traces extend it:
- `tx_context.pil`: Tree states and side effect management
- `tx_discard.pil`: Discard flag management for reverts

### Key Characteristics
- 12 phases: NR_NULLIFIER_INSERTION through CLEANUP
- Public call dispatch to execution.pil
- Tree state tracking (note hash, nullifier, public data, etc.)
- Revert handling with state restoration

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/tx.pil` | Main PIL constraints (748 lines) |
| `barretenberg/cpp/pil/vm2/tx_context.pil` | Tree/side effect state (493 lines) |
| `barretenberg/cpp/pil/vm2/tx_discard.pil` | Discard flag management (59 lines) |

---

## 3. Constraint Analysis

### 3.1 Trace Shape (tx.pil)

**TRACE_CONTINUITY (line 110)**:
```
(1 - precomputed.first_row) * (1 - sel) * sel' = 0
```

**START_WITH_SEL (line 115)**:
```
start_tx' = precomputed.first_row
```

**NO_EARLY_END (line 162)**:
```
sel * (1 - sel') * (phase_value - constants.AVM_TX_PHASE_VALUE_LAST) = 0
```

### 3.2 Phase Management

**START_PHASE_VALUE_INITIALIZATION (line 171)**:
```
start_tx * (phase_value - constants.AVM_TX_PHASE_VALUE_START) = 0
```

**PHASE_VALUE_CONTINUITY (line 176)**:
```
NOT_PHASE_END * (phase_value' - phase_value) = 0
```

**INCR_PHASE_VALUE_ON_END (line 179)**:
```
sel' * (1 - reverted) * end_phase * (phase_value' - (phase_value + 1)) = 0
```

**PHASE_JUMP_ON_REVERT (line 228)**:
```
reverted * (next_phase_on_revert - phase_value') = 0
```

### 3.3 Phase Spec Lookup

**READ_PHASE_SPEC (line 187)**:
```
sel { phase_value, is_public_call_request, is_teardown, is_collect_fee, ... }
in precomputed.sel_phase { precomputed.clk, ... };
```
- Ensures phase attributes come from precomputed table

### 3.4 Public Call Dispatch

**DISPATCH_EXEC_START (line 319)**:
```
should_process_call_request { next_context_id, discard, msg_sender, contract_addr, fee, is_static, calldata_size, [tree states], [gas info] }
is execution.enqueued_call_start { ... };
```

**DISPATCH_EXEC_END (line 393)**:
```
should_process_call_request { next_context_id, next_context_id', reverted, discard, [tree states], [gas info] }
is execution.enqueued_call_end { ... };
```

### 3.5 Tree State Management (tx_context.pil)

**State Continuity (lines 245-277)**:
```
NOT_LAST_ROW * (1 - reverted) * (next_note_hash_tree_root - prev_note_hash_tree_root') = 0
```
- Tree states propagate forward unless reverted

**RESTORE_STATE_ON_REVERT (line 288)**:
```
reverted { setup_phase_value, ..., prev_*' }
in tx.sel { phase_value, end_phase, next_* };
```
- On revert, restore to end-of-setup state

**Immutability constraints (lines 343-417)**:
- Trees can only change in appropriate phases
- Padded rows cannot change state

### 3.6 Discard Management (tx_discard.pil)

**CAN_ONLY_DISCARD_IN_REVERTIBLE_PHASES (line 28)**:
```
discard * (1 - is_revertible) = 0
```

**REVERTED_MUST_DISCARD (line 32)**:
```
reverted * (1 - discard) = 0
```

**DISCARD_PROPAGATION (line 50)**:
```
sel * PROPAGATE_DISCARD * (discard' - discard) = 0
```
Where `PROPAGATE_DISCARD = (1 - LAST_ROW_OF_SETUP) * (1 - reverted)`.

---

## 4. Soundness Analysis

### 4.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Skip phases | READ_PHASE_SPEC + phase increment | PROTECTED |
| Wrong phase order | Precomputed table + INCR_PHASE_VALUE | PROTECTED |
| Forge call results | DISPATCH_EXEC_START/END permutations | PROTECTED |
| Wrong revert target | next_phase_on_revert from precomputed | PROTECTED |
| State after revert | RESTORE_STATE_ON_REVERT lookup | PROTECTED |
| Discard in non-revertible | CAN_ONLY_DISCARD_IN_REVERTIBLE | PROTECTED |
| Modify immutable state | Immutability constraints | PROTECTED |

### 4.2 Critical Constraints Verified

1. **Phase Ordering**: Phases increment by 1 (or jump via next_phase_on_revert)
2. **Call Dispatch**: Uses permutations for secure context binding
3. **State Restoration**: Lookup ensures correct end-of-setup state
4. **Discard Logic**: Propagates correctly, only in revertible phases

### 4.3 Collect Fee Phase Security

The fee collection phase:
1. Reads effective fee rates from public inputs
2. Computes fee = da_gas * da_rate + l2_gas * l2_rate
3. Derives balance slot via Poseidon2
4. Validates fee <= balance via ff_gt
5. Writes new balance via public_data_check

### 4.4 Tree Padding Phase

**PAD_NOTE_HASH_TREE (line 735)**:
```
is_tree_padding * ((prev_note_hash_tree_size + constants.MAX_NOTE_HASHES_PER_TX - prev_num_note_hashes_emitted) - next_note_hash_tree_size) = 0
```
- Pads trees to fixed size for circuit consistency

---

## 5. Findings

### No Critical Vulnerabilities Found

The tx.pil gadget suite is **SOUND**.

### INFO-1: next_context_id Binding

The constraint `next_context_id' = execution.next_context_id` at enqueued_call_end ensures:
- No reordering of enqueued calls
- Context IDs are sequential across calls

### INFO-2: Discard Toggle Prevention

From tx_discard.pil comment (lines 52-58):
- If malicious prover sets `discard = 1` without revert, it propagates to collect_fee
- At collect_fee, `is_revertible = 0` but `discard = 1` violates CAN_ONLY_DISCARD_IN_REVERTIBLE

### INFO-3: tx_reverted Tracking

`tx_reverted` column starts as 0 and flips to 1 on first revert, remaining 1 thereafter. Written to public inputs at cleanup.

---

## 6. Conclusion

**Status**: SOUND

The tx.pil gadget suite correctly implements transaction lifecycle management with:
- Proper phase sequencing
- Secure call dispatch and result retrieval
- Revert handling with state restoration
- Discard flag propagation
- Tree state immutability enforcement

The constraint system is complete and no soundness vulnerabilities were identified.

---

## Appendix: Phase Table

| Phase | Value | Description |
|-------|-------|-------------|
| NR_NULLIFIER_INSERTION | 0 | Non-revertible nullifiers |
| NR_NOTE_HASH_INSERTION | 1 | Non-revertible note hashes |
| NR_L2_TO_L1_MESSAGE_INSERTION | 2 | Non-revertible messages |
| SETUP | 3 | Setup enqueued calls |
| R_NULLIFIER_INSERTION | 4 | Revertible nullifiers |
| R_NOTE_HASH_INSERTION | 5 | Revertible note hashes |
| R_L2_TO_L1_MESSAGE_INSERTION | 6 | Revertible messages |
| APP_LOGIC | 7 | App logic calls |
| TEARDOWN | 8 | Teardown call |
| COLLECT_FEE | 9 | Fee collection |
| TREE_PADDING | 10 | Tree size padding |
| CLEANUP | 11 | Final cleanup |
