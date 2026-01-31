# Deep Security Audit: opcodes/*.pil (13 files)

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL files: 13 files in `pil/vm2/opcodes/`
- [x] Located dependencies: gt, ff_gt, range_check, memory, public_inputs, precomputed, trees/*
- [x] Located callers: execution.pil (dispatch selectors)

### Phase 2: Understanding
- [x] Documented opcode purposes
- [x] Listed all witnesses
- [x] Listed all constraints
- [x] Understood error handling patterns

### Phase 3: Soundness
- [x] Verified limit checks
- [x] Analyzed error consolidation
- [x] Checked static context enforcement
- [x] Verified lookup/permutation usage

### Phase 4: Completeness
- [x] Reviewed error conditions
- [x] Checked edge cases (limits, bounds)
- [x] Verified state updates

### Phase 5: Integration
- [x] Verified execution dispatch
- [x] Checked tree gadget interactions
- [x] Verified public inputs interactions

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `emit_notehash.pil` | 64 | EMIT_NOTEHASH opcode |
| `emit_nullifier.pil` | 91 | EMIT_NULLIFIER opcode |
| `emit_unencrypted_log.pil` | 296 | EMIT_UNENCRYPTED_LOG opcode |
| `external_call.pil` | 79 | CALL/STATICCALL gas clamping |
| `get_contract_instance.pil` | 235 | GETCONTRACTINSTANCE opcode |
| `get_env_var.pil` | 154 | GETENVVAR opcode |
| `internal_call.pil` | 95 | INTERNAL_CALL/RETURN opcodes |
| `l1_to_l2_message_exists.pil` | 62 | L1_TO_L2_MESSAGE_EXISTS opcode |
| `notehash_exists.pil` | 65 | NOTEHASH_EXISTS opcode |
| `nullifier_exists.pil` | 55 | NULLIFIER_EXISTS opcode |
| `send_l2_to_l1_msg.pil` | 89 | SEND_L2_TO_L1_MSG opcode |
| `sload.pil` | 44 | SLOAD opcode |
| `sstore.pil` | 110 | SSTORE opcode |

---

## 2. Common Patterns

### 2.1 Limit Check Pattern

```pil
pol REMAINING_WRITES = MAX_WRITES - prev_count;
pol commit reached_limit_inv;
sel * (REMAINING_WRITES * (reached_limit * (1 - reached_limit_inv) + reached_limit_inv) - 1 + reached_limit) = 0;
```

Zero-check pattern to detect when `REMAINING_WRITES = 0`.

### 2.2 Error Consolidation Pattern

```pil
// OR of multiple error conditions
sel * ((1 - err1) * (1 - err2) * (1 - err3) - (1 - total_error)) = 0;
```

### 2.3 Static Context Check

```pil
// State-changing ops error in static context
sel * (1 - is_static) * ... = ...
```

### 2.4 State Update on Error

```pil
// Root unchanged on error
sel * error * (prev_root - root) = 0;
// Size unchanged on error
sel * error * (prev_size - size) = 0;
```

---

## 3. emit_notehash.pil

### 3.1 Purpose

Emits a note hash to the note hash tree.

### 3.2 Key Constraints

```pil
// emit_notehash.pil:20-21
#[MAX_NOTE_HASHES_REACHED]
sel_execute_emit_notehash * (REMAINING_NOTE_HASH_WRITES * (sel_reached_max_note_hashes * (1 - remaining_note_hashes_inv) + remaining_note_hashes_inv) - 1 + sel_reached_max_note_hashes) = 0;

// emit_notehash.pil:24-25
#[OPCODE_ERROR_IF_MAX_NOTE_HASHES_REACHED_OR_STATIC]
sel_execute_emit_notehash * ((1 - sel_reached_max_note_hashes) * (1 - is_static) - (1 - sel_opcode_error)) = 0;

// emit_notehash.pil:33-54
#[NOTEHASH_TREE_WRITE]
sel_write_note_hash { ... } in note_hash_tree_check.write { ... };
```

### 3.3 Security Analysis

| Property | Protection |
|----------|------------|
| Max limit | Zero-check on REMAINING |
| Static context | is_static check |
| Tree write | Lookup to note_hash_tree_check |
| Root on error | #[EMIT_NOTEHASH_TREE_ROOT_NOT_CHANGED] |

---

## 4. emit_nullifier.pil

### 4.1 Purpose

Emits a nullifier to the nullifier tree with collision detection.

### 4.2 Key Constraints

```pil
// emit_nullifier.pil:41-42
#[MAX_NULLIFIER_WRITES_REACHED]
sel_execute_emit_nullifier * (REMAINING_NULLIFIER_WRITES * (...) - 1 + sel_reached_max_nullifiers) = 0;

// emit_nullifier.pil:58-79
#[WRITE_NULLIFIER]
sel_write_nullifier {
    register[0], prev_nullifier_tree_root,
    /*exists=*/ sel_opcode_error, // collision = error
    nullifier_tree_root, ...
} in nullifier_check.write { ... };
```

### 4.3 Security Analysis

| Property | Protection |
|----------|------------|
| Max limit | Zero-check |
| Static context | is_static check |
| Collision detection | `exists` output from nullifier_check |
| Silo enforced | should_silo = 1 always |

---

## 5. emit_unencrypted_log.pil

### 5.1 Purpose

Multi-row gadget for emitting unencrypted logs to public inputs.

### 5.2 Key Constraints

```pil
// emit_unencrypted_log.pil:133-136
#[CHECK_MEMORY_OUT_OF_BOUNDS]
start { end_log_address_upper_bound, max_mem_size, error_out_of_bounds }
in gt.sel_others { ... };

// emit_unencrypted_log.pil:156-159
#[CHECK_LOG_FIELDS_COUNT]
start { expected_next_log_fields, public_logs_payload_length, error_too_many_log_fields }
in gt.sel { ... };

// emit_unencrypted_log.pil:182-186
#[WRONG_TAG_CHECK]
NOT_END * ((1 - seen_wrong_tag) * WRONG_NEXT_TAG + seen_wrong_tag - seen_wrong_tag') = 0;
end * (error_tag_mismatch - seen_wrong_tag) = 0;

// emit_unencrypted_log.pil:239-249
#[READ_MEM]
sel_should_read_memory { ... } is memory.sel_unencrypted_log_read { ... };

// emit_unencrypted_log.pil:287-295
#[WRITE_DATA_TO_PUBLIC_INPUTS]
sel_should_write_to_public_inputs { public_inputs_index, public_inputs_value }
in public_inputs.sel { ... };
```

### 5.3 Security Analysis

| Property | Protection |
|----------|------------|
| Memory bounds | GT lookup |
| Field count limit | GT lookup |
| Tag validation | seen_wrong_tag propagation |
| Memory read | Permutation to memory |
| PI write | Lookup (read-only) |
| Ghost row prevention | sel gating |

---

## 6. external_call.pil

### 6.1 Purpose

Gas clamping for CALL/STATICCALL opcodes.

### 6.2 Key Constraints

```pil
// external_call.pil:43-44
pol commit l2_gas_left;
l2_gas_left = sel_enter_call * (l2_gas_limit - l2_gas_used);

// external_call.pil:58-59
#[IS_L2_GAS_LEFT_GT_ALLOCATED]
sel_enter_call { l2_gas_left, register[0], is_l2_gas_left_gt_allocated } in gt.sel_others { ... };

// external_call.pil:63
sel_enter_call * ((register[0] - l2_gas_left) * is_l2_gas_left_gt_allocated + l2_gas_left - l2_gas_limit') = 0;
```

### 6.3 Security Analysis

Gas clamping ensures `new_gas_limit = min(allocated, remaining)` via GT comparison.

---

## 7. get_contract_instance.pil

### 7.1 Purpose

Retrieves contract instance members (deployer, class_id, init_hash).

### 7.2 Key Constraints

```pil
// get_contract_instance.pil:111-112
#[WRITE_OUT_OF_BOUNDS_CHECK]
sel * (DST_OFFSET_DIFF_MAX * (WRITES_OUT_OF_BOUNDS * (1 - dst_offset_diff_max_inv) + dst_offset_diff_max_inv) - 1 + WRITES_OUT_OF_BOUNDS) = 0;

// get_contract_instance.pil:122-139
#[PRECOMPUTED_INFO]
is_valid_writes_in_bounds { member_enum, is_valid_member_enum, ... }
in precomputed.sel_range_8 { ... };

// get_contract_instance.pil:161-182
#[CONTRACT_INSTANCE_RETRIEVAL]
is_valid_member_enum { contract_address, ... }
in contract_instance_retrieval.sel { ... };

// get_contract_instance.pil:201-216, 219-234
#[MEM_WRITE_CONTRACT_INSTANCE_EXISTS]
#[MEM_WRITE_CONTRACT_INSTANCE_MEMBER]
is_valid_member_enum { ... } is memory.sel_get_contract_instance_*_write { ... };
```

### 7.3 Security Analysis

| Property | Protection |
|----------|------------|
| Bounds check | Zero-check on DST_OFFSET_DIFF_MAX |
| Enum validation | Precomputed lookup |
| Instance retrieval | contract_instance_retrieval lookup |
| Memory writes | Permutations |
| Ghost row prevention | #[IS_VALID_WRITES_IN_BOUNDS_REQUIRES_SEL] |

---

## 8. get_env_var.pil

### 8.1 Purpose

Retrieves environment variables from context or public inputs.

### 8.2 Key Constraints

```pil
// get_env_var.pil:87-104
#[PRECOMPUTED_INFO]
sel_execute_get_env_var {
    rop[1], sel_opcode_error, sel_envvar_pi_lookup_col0, ...
} in precomputed.sel_range_8 { ... };

// get_env_var.pil:110-122
#[READ_FROM_PUBLIC_INPUTS_COL0]
sel_envvar_pi_lookup_col0 { envvar_pi_row_idx, value_from_pi }
in public_inputs.sel { ... };

// get_env_var.pil:138-153
#[ADDRESS_FROM_CONTEXT]
sel_execute_get_env_var * is_address * (register[0] - contract_address) = 0;
// Similar for sender, transaction_fee, is_static, l2_gas_left, da_gas_left
```

### 8.3 Security Analysis

Enum validation via precomputed lookup ensures only valid env vars are accessible.

---

## 9. internal_call.pil

### 9.1 Purpose

Manages internal call/return with call stack.

### 9.2 Key Constraints

```pil
// internal_call.pil:45-46
#[INTERNAL_RET_ERROR]
sel_execute_internal_return * (internal_call_return_id * (sel_opcode_error * (1 - internal_call_return_id_inv) + internal_call_return_id_inv) - 1 + sel_opcode_error) = 0;

// internal_call.pil:74-79
#[PUSH_CALL_STACK]
sel_execute_internal_call {
    context_id, next_internal_call_id, internal_call_id, internal_call_return_id, next_pc
} is internal_call_stack.sel { ... };

// internal_call.pil:89-94
#[UNWIND_CALL_STACK]
sel_read_unwind_call_stack {
    context_id, internal_call_id, internal_call_id', internal_call_return_id', pc'
} in internal_call_stack.sel { ... };
```

### 9.3 Security Analysis

| Property | Protection |
|----------|------------|
| Empty stack return | Zero-check on return_id |
| Push | Permutation (bijective) |
| Pop | Lookup (after push) |
| ID management | Explicit constraints |

---

## 10. l1_to_l2_message_exists.pil

### 10.1 Purpose

Checks if L1→L2 message exists at a leaf index.

### 10.2 Key Constraints

```pil
// l1_to_l2_message_exists.pil:28-37
#[L1_TO_L2_MSG_LEAF_INDEX_IN_RANGE]
sel_execute_l1_to_l2_message_exists {
    l1_to_l2_msg_tree_leaf_count, register[1], l1_to_l2_msg_leaf_in_range
} in gt.sel_others { ... };

// l1_to_l2_message_exists.pil:40-41
#[L1_TO_L2_MSG_EXISTS_OUT_OF_RANGE_FALSE]
sel_execute_l1_to_l2_message_exists * (1 - l1_to_l2_msg_leaf_in_range) * register[2] = 0;

// l1_to_l2_message_exists.pil:44-55
#[L1_TO_L2_MSG_READ]
l1_to_l2_msg_leaf_in_range { ... } in l1_to_l2_message_tree_check.sel { ... };
```

### 10.3 Security Analysis

| Property | Protection |
|----------|------------|
| Index bounds | GT check against leaf count |
| Out-of-range → false | Explicit constraint |
| Tree read | Lookup |
| Output tag | U1 enforced |

---

## 11. notehash_exists.pil

### 11.1 Purpose

Checks if note hash exists at a leaf index.

### 11.2 Key Constraints

Similar structure to l1_to_l2_message_exists.pil with note_hash_tree_check lookup.

### 11.3 Security Analysis

Same pattern as l1_to_l2_message_exists - index bounds via GT, tree lookup.

---

## 12. nullifier_exists.pil

### 12.1 Purpose

Checks if a siloed nullifier exists.

### 12.2 Key Constraints

```pil
// nullifier_exists.pil:32-47
#[NULLIFIER_EXISTS_CHECK]
sel_execute_nullifier_exists {
    register[1], register[0], prev_nullifier_tree_root, precomputed.zero
} in nullifier_check.sel { ... };
```

### 12.3 Security Analysis

| Property | Protection |
|----------|------------|
| Existence check | nullifier_check lookup |
| No siloing | should_silo = 0 (already siloed) |
| Output tag | U1 enforced |

---

## 13. send_l2_to_l1_msg.pil

### 13.1 Purpose

Sends L2→L1 message with recipient and content.

### 13.2 Key Constraints

```pil
// send_l2_to_l1_msg.pil:39-40
#[MAX_WRITES_REACHED]
sel_execute_send_l2_to_l1_msg * (REMAINING_L2_TO_L1_MSG_WRITES * (...) - 1 + sel_l2_to_l1_msg_limit_error) = 0;

// send_l2_to_l1_msg.pil:48-57
#[RECIPIENT_CHECK]
sel_execute_send_l2_to_l1_msg { register[0], max_eth_address_value, sel_too_large_recipient_error }
in ff_gt.sel_gt { ... };

// send_l2_to_l1_msg.pil:73-84
#[WRITE_L2_TO_L1_MSG]
sel_write_l2_to_l1_msg { public_inputs_index, register[0], register[1], contract_address }
in public_inputs.sel { ... };
```

### 13.3 Security Analysis

| Property | Protection |
|----------|------------|
| Max limit | Zero-check |
| Static context | is_static check |
| Recipient bounds | ff_gt check (20-byte Ethereum address) |
| PI write | Lookup |

---

## 14. sload.pil

### 14.1 Purpose

Reads value from storage at slot.

### 14.2 Key Constraints

```pil
// sload.pil:26-37
#[STORAGE_READ]
sel_execute_sload {
    register[0], register[1], register[2], prev_public_data_tree_root
} in public_data_check.sel { ... };
```

### 14.3 Security Analysis

Simple storage read via public_data_check lookup. Output tagged as FF.

---

## 15. sstore.pil

### 15.1 Purpose

Writes value to storage at slot with data write limit tracking.

### 15.2 Key Constraints

```pil
// sstore.pil:36-37
#[SSTORE_MAX_DATA_WRITES_REACHED]
sel_execute_sstore * (REMAINING_DATA_WRITES * (...) - 1 + max_data_writes_reached) = 0;

// sstore.pil:44-45
#[OPCODE_ERROR_IF_OVERFLOW_OR_STATIC]
sel_execute_sstore * ((1 - max_data_writes_reached * dynamic_da_gas_factor) * (1 - is_static) - (1 - sel_opcode_error)) = 0;

// sstore.pil:57-74
#[RECORD_WRITTEN_STORAGE_SLOT]
sel_write_public_data { ... } in written_public_data_slots_tree_check.sel { ... };

// sstore.pil:76-97
#[STORAGE_WRITE]
sel_write_public_data { ... } is public_data_check.non_protocol_write { ... };
```

### 15.3 Security Analysis

| Property | Protection |
|----------|------------|
| Max data writes | Zero-check |
| Dynamic gas | Based on first write vs rewrite |
| Static context | is_static check |
| Slot tracking | written_public_data_slots_tree_check lookup |
| Tree write | Permutation to public_data_check |
| Roots on error | Explicit constraints |

---

## 16. Soundness Verification

### 16.1 Overall Attack Surface

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Exceed limits | Zero-check pattern | PROTECTED |
| Static context violation | is_static check | PROTECTED |
| Invalid enum | Precomputed lookup | PROTECTED |
| Memory out-of-bounds | GT check | PROTECTED |
| Forge tree operations | Tree gadget lookups | PROTECTED |
| Malicious memory write | Permutations | PROTECTED |
| Ghost row injection | sel gating | PROTECTED |
| Call stack manipulation | Permutation for push | PROTECTED |
| Skip error handling | Error consolidation | PROTECTED |

### 16.2 Critical Security Properties

#### 16.2.1 Limit Enforcement

All emit opcodes enforce `REMAINING <= 0` via zero-check pattern.

#### 16.2.2 Static Context

State-changing opcodes (emit_*, send_*, sstore) all check `is_static`.

#### 16.2.3 Error Consolidation

Multiple error conditions properly combined with `(1 - err1) * (1 - err2) * ...` pattern.

#### 16.2.4 State Preservation on Error

All state-changing opcodes preserve roots/sizes on error:
- `sel * error * (prev_root - root) = 0`

---

## 17. Findings

### No Critical Vulnerabilities Found

All opcode gadgets are **SOUND**.

### INFO-1: Virtual Gadget Pattern

Most opcodes are "virtual gadgets" sharing rows with execution trace:
```pil
namespace execution; // this is a virtual gadget that shares rows with the execution trace
```

### INFO-2: Infallible Opcodes

Several opcodes are marked infallible:
- sload, nullifier_exists, notehash_exists, l1_to_l2_message_exists

Enforced by `#[INFALLIBLE_OPCODES_SUCCESS]` in execution.pil.

### INFO-3: Discard Flag

The `discard` flag prevents PI writes for reverted operations while still counting toward limits:
```pil
// Increase count even in discard case
prev_count + (1 - error) * ... - count
```

### INFO-4: Internal Call Stack

Uses permutation for push (ensures bijection) but lookup for pop (after push verified):
```pil
#[PUSH_CALL_STACK]
... is internal_call_stack.sel { ... };  // permutation

#[UNWIND_CALL_STACK]
... in internal_call_stack.sel { ... };  // lookup
```

### INFO-5: Recipient Validation

send_l2_to_l1_msg validates recipient fits in 20-byte Ethereum address using ff_gt.

---

## 18. Conclusion

**Status**: SOUND

All 13 opcode gadgets are **correctly implemented** with:

**Emit opcodes** (notehash, nullifier, unencrypted_log):
- Proper limit checking
- Static context enforcement
- Tree write lookups/permutations

**Existence check opcodes** (notehash, nullifier, l1_to_l2_message):
- Index bounds validation
- Tree read lookups
- Proper output tagging (U1)

**Storage opcodes** (sload, sstore):
- Tree lookups/permutations
- Data write limit tracking
- Static context enforcement

**Call opcodes** (external_call, internal_call):
- Gas clamping via GT
- Call stack via permutation/lookup

**Other opcodes** (get_contract_instance, get_env_var, send_l2_to_l1_msg):
- Enum validation via precomputed
- Memory bounds checking
- PI read/write lookups

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary by File

### emit_notehash.pil
| Constraint | Purpose |
|------------|---------|
| MAX_NOTE_HASHES_REACHED | Limit check |
| OPCODE_ERROR_IF_MAX_NOTE_HASHES_REACHED_OR_STATIC | Error condition |
| NOTEHASH_TREE_WRITE | Tree write |
| EMIT_NOTEHASH_TREE_ROOT_NOT_CHANGED | Root on error |
| EMIT_NOTEHASH_TREE_SIZE_INCREASE | Size update |

### emit_nullifier.pil
| Constraint | Purpose |
|------------|---------|
| MAX_NULLIFIER_WRITES_REACHED | Limit check |
| VALIDATION_ERROR_DISABLE_WRITE | Gate write |
| WRITE_NULLIFIER | Tree write + collision |
| EMIT_NULLIFIER_TREE_ROOT_NOT_CHANGED | Root on error |

### emit_unencrypted_log.pil
| Constraint | Purpose |
|------------|---------|
| CHECK_MEMORY_OUT_OF_BOUNDS | Memory bounds |
| CHECK_LOG_FIELDS_COUNT | Field count limit |
| WRONG_TAG_CHECK | Tag validation |
| READ_MEM | Memory permutation |
| WRITE_DATA_TO_PUBLIC_INPUTS | PI lookup |

### sstore.pil
| Constraint | Purpose |
|------------|---------|
| SSTORE_MAX_DATA_WRITES_REACHED | Limit check |
| OPCODE_ERROR_IF_OVERFLOW_OR_STATIC | Error condition |
| RECORD_WRITTEN_STORAGE_SLOT | Track slot |
| STORAGE_WRITE | Tree permutation |
| SSTORE_*_NOT_CHANGED | State on error |
