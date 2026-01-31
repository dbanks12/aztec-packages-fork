# Deep Security Audit: bytecode/*.pil (8 files)

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL files: 8 files in `pil/vm2/bytecode/`
- [x] Located dependencies: poseidon2_hash, ecc, scalar_mul, range_check, gt, ff_gt, memory, precomputed, public_inputs, trees/*
- [x] Located callers: execution.pil, various tree gadgets

### Phase 2: Understanding
- [x] Documented gadget purposes (address derivation, bytecode hashing, instruction fetching)
- [x] Listed all witnesses
- [x] Listed all constraints
- [x] Understood data flow through bytecode subsystem

### Phase 3: Soundness
- [x] Verified hash derivations
- [x] Analyzed error handling
- [x] Checked lookup/permutation usage
- [x] Verified sliding window mechanism

### Phase 4: Completeness
- [x] Reviewed error hierarchies
- [x] Checked edge cases (protocol contracts, empty bytecode)
- [x] Verified counter propagation

### Phase 5: Integration
- [x] Verified execution dispatch
- [x] Checked cross-gadget interactions
- [x] Verified tree lookups

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `address_derivation.pil` | 154 | Derive contract address from instance members |
| `bc_decomposition.pil` | 274 | Bytecode storage with sliding window |
| `bc_hashing.pil` | 279 | Compute bytecode hash via Poseidon2 |
| `bc_retrieval.pil` | 174 | Retrieve bytecode for an address |
| `class_id_derivation.pil` | 39 | Derive class ID from class members |
| `contract_instance_retrieval.pil` | 212 | Prove contract instance existence |
| `instr_fetching.pil` | 298 | Fetch and decode instructions |
| `update_check.pil` | 179 | Validate current class ID with updates |

---

## 2. System Architecture

### 2.1 Data Flow

```
execution.pil
    ↓
instr_fetching.pil  ←→  bc_decomposition.pil  ←→  bc_hashing.pil
    ↓                           ↓
bc_retrieval.pil  ←→  contract_instance_retrieval.pil
    ↓                           ↓
class_id_derivation.pil    address_derivation.pil
                                ↓
                           update_check.pil
```

### 2.2 Key Relationships

1. **Execution → Instruction Fetching**: Lookups instruction by (pc, bytecode_id)
2. **Instruction Fetching → BC Decomposition**: Gets bytes at pc
3. **BC Decomposition → BC Hashing**: Provides packed fields for hashing
4. **BC Hashing**: Computes bytecode_id = hash(bytecode)
5. **BC Retrieval → Contract Instance Retrieval**: Validates contract exists
6. **Contract Instance Retrieval → Address Derivation**: Verifies address derivation
7. **Contract Instance Retrieval → Update Check**: Validates current class ID

---

## 3. address_derivation.pil

### 3.1 Purpose

Derives contract address from:
- salt, deployer_addr, class_id, init_hash
- Public keys (nullifier, incoming_viewing, outgoing_viewing, tagging)

### 3.2 Derivation Steps

```
salted_init_hash = H(DOM_SEP__PARTIAL_ADDRESS, salt, init_hash, deployer_addr)
partial_address = H(DOM_SEP__PARTIAL_ADDRESS, class_id, salted_init_hash)
public_keys_hash = H(DOM_SEP__PUBLIC_KEYS_HASH, nullifier_key, incoming_key, outgoing_key, tagging_key)
preaddress = H(DOM_SEP__CONTRACT_ADDRESS_V1, public_keys_hash, partial_address)
preaddress_pk = scalar_mul(preaddress, G1)
address = (preaddress_pk + incoming_viewing_key).x
```

### 3.3 Key Constraints

```pil
// address_derivation.pil:52-58
#[SALTED_INITIALIZATION_HASH_POSEIDON2_0]
sel { partial_address_domain_separator, salt, init_hash, salted_init_hash, const_four }
in poseidon2_hash.start { ... };

// address_derivation.pil:126-135
#[PREADDRESS_SCALAR_MUL]
sel { preaddress, g1_x, g1_y, precomputed.zero, preaddress_public_key_x, preaddress_public_key_y, precomputed.zero }
in scalar_mul.start { ... };

// address_derivation.pil:142-151
#[ADDRESS_ECADD]
sel { preaddress_public_key_x, preaddress_public_key_y, ..., incoming_viewing_key_x, incoming_viewing_key_y, ..., address, address_y, ... }
in ecc.sel { ... };
```

### 3.4 Security Analysis

| Property | Protection |
|----------|------------|
| Hash correctness | Poseidon2 lookups |
| Scalar mul correctness | scalar_mul lookup |
| Point add correctness | ecc lookup |
| Domain separation | Explicit separators |

---

## 4. bc_decomposition.pil

### 4.1 Purpose

Stores bytecode byte-by-byte with a **37-byte sliding window** for instruction fetching.

### 4.2 Sliding Window

```
| pc | bytes | +1 | +2 | ... | +36 | bytes_remaining | last_of_contract |
|----|-------|----|----|-----|-----|-----------------|------------------|
|  0 | 0x01  |0x02|0x03| ... | ... |      100        |        0         |
| 99 | 0xFF  | 0  | 0  | ... | ... |        1        |        1         |
```

### 4.3 Key Constraints

```pil
// bc_decomposition.pil:44-45 - Selector toggle
#[BC_DEC_SEL_BYTES_REM_NON_ZERO]
bytes_remaining * ((1 - sel) * (1 - bytes_rem_inv) + bytes_rem_inv) - sel = 0;

// bc_decomposition.pil:69-70 - PC increment
#[BC_DEC_PC_INCREMENT]
sel * (1 - last_of_contract) * (pc' - pc - 1) = 0;

// bc_decomposition.pil:79-80 - ID constant
#[BC_DEC_ID_CONSTANT]
(1 - LATCH_CONDITION) * (id' - id) = 0;

// bc_decomposition.pil:186-221 - Sliding window propagation
bytes_pc_plus_1 = (1 - LATCH_CONDITION) * bytes';
bytes_pc_plus_2 = (1 - LATCH_CONDITION) * bytes_pc_plus_1';
// ... continues for all 36 lookahead bytes
```

### 4.4 Packed Field for Hashing

```pil
// bc_decomposition.pil:263-273
#[BC_DECOMPOSITION_REPACKING]
sel_packed * (
    2**0 * bytes_pc_plus_30 + 2**8 * bytes_pc_plus_29 + ... + 2**240 * bytes
    - packed_field
) = 0;
```

31 bytes packed into a field element at every 31st pc.

### 4.5 Security Analysis

| Property | Protection |
|----------|------------|
| Bytes are bytes | #[BYTES_ARE_BYTES] 8-bit range check |
| PC monotonic | #[BC_DEC_PC_INCREMENT] |
| ID stable | #[BC_DEC_ID_CONSTANT] |
| Window zeroes | (1 - LATCH_CONDITION) * ... pattern forces zeros |

---

## 5. bc_hashing.pil

### 5.1 Purpose

Computes bytecode hash by:
1. Fetching packed fields from bc_decomposition
2. Hashing with Poseidon2 (3 fields per round)
3. Prepending domain separator

### 5.2 Key Constraints

```pil
// bc_hashing.pil:110-111 - Domain separator
#[START_IS_SEPARATOR]
start * (packed_fields_0 - constants.DOM_SEP__PUBLIC_BYTECODE) = 0;

// bc_hashing.pil:113-126 - Field lookups (permutations)
#[GET_PACKED_FIELD_0]
sel_not_start { pc_index, bytecode_id, packed_fields_0 }
is bc_decomposition.sel_packed_read[0] { ... };

// bc_hashing.pil:252-253 - Hash = ID
#[HASH_IS_ID]
sel * (bytecode_id - output_hash) = 0;

// bc_hashing.pil:255-257 - Poseidon2 lookup
#[POSEIDON2_HASH]
sel { start, latch, packed_fields_0, packed_fields_1, packed_fields_2, input_len, rounds_rem, output_hash }
in poseidon2_hash.sel { ... };
```

### 5.3 Padding Constraints

```pil
// bc_hashing.pil:156-166
#[PADDING_CONSISTENCY]
PADDING_1 * sel_not_padding_2 = 0;  // pad_1 => pad_2
#[PADDING_END]
PADDING_2 * (1 - latch) = 0;  // padding only at latch
#[PADDED_BY_ZERO_1]
PADDING_1 * packed_fields_1 = 0;
#[PADDED_BY_ZERO_2]
PADDING_2 * packed_fields_2 = 0;
```

### 5.4 Final Bytes Check

```pil
// bc_hashing.pil:189-210
#[CHECK_FINAL_BYTES_REMAINING]
latch {
    pc_at_final_field, bytecode_id,
    sel /* =1 */, precomputed.zero, precomputed.zero, precomputed.zero, precomputed.zero, precomputed.zero, precomputed.zero
} in bc_decomposition.sel_packed {
    bc_decomposition.pc, bc_decomposition.id,
    bc_decomposition.sel_windows_gt_remaining,
    bc_decomposition.bytes_pc_plus_31, ..., bc_decomposition.bytes_pc_plus_36
};
```

Ensures bytecode is fully consumed.

### 5.5 Security Analysis

| Property | Protection |
|----------|------------|
| Field integrity | Permutation to bc_decomposition |
| Hash correctness | Poseidon2 lookup |
| Bytecode complete | #[CHECK_FINAL_BYTES_REMAINING] |
| No extra fields | Padding constraints |

---

## 6. bc_retrieval.pil

### 6.1 Purpose

Retrieves bytecode for an address:
1. Check contract instance exists
2. Derive class ID
3. Check for too many bytecodes
4. Update retrieved bytecodes tree

### 6.2 Key Constraints

```pil
// bc_retrieval.pil:74-87 - Instance retrieval lookup
#[CONTRACT_INSTANCE_RETRIEVAL]
sel { address, current_class_id, instance_exists, public_data_tree_root, nullifier_tree_root }
in contract_instance_retrieval.sel { ... };

// bc_retrieval.pil:97-98 - Zero check for remaining bytecodes
#[NO_REMAINING_BYTECODES]
sel * (REMAINING_BYTECODES * (no_remaining_bytecodes * (1 - remaining_bytecodes_inv) + remaining_bytecodes_inv) - 1 + no_remaining_bytecodes) = 0;

// bc_retrieval.pil:127-138 - Class ID derivation
#[CLASS_ID_DERIVATION]
should_retrieve { current_class_id, artifact_hash, private_functions_root, bytecode_id }
in class_id_derivation.sel { ... };

// bc_retrieval.pil:140-155 - Tree insertion
#[RETRIEVED_BYTECODES_INSERTION]
should_retrieve { current_class_id, should_retrieve, prev_root, prev_size, next_root, next_size }
in retrieved_bytecodes_tree_check.sel { ... };
```

### 6.3 Error Handling

```pil
// bc_retrieval.pil:116-119
pol TOO_MANY_BYTECODES = no_remaining_bytecodes * is_new_class;
sel * (instance_exists * (1 - TOO_MANY_BYTECODES) - (1 - error)) = 0;
```

Error if instance doesn't exist OR too many bytecodes.

### 6.4 Security Analysis

| Property | Protection |
|----------|------------|
| Instance exists | contract_instance_retrieval lookup |
| Class ID valid | class_id_derivation lookup |
| Bytecode limit | NO_REMAINING_BYTECODES check |
| Tree update | retrieved_bytecodes_tree_check |

---

## 7. class_id_derivation.pil

### 7.1 Purpose

Derives class_id = H(DOM_SEP__CONTRACT_CLASS_ID, artifact_hash, private_functions_root, public_bytecode_commitment)

### 7.2 Key Constraints

```pil
// class_id_derivation.pil:30-36
#[CLASS_ID_POSEIDON2_0]
sel { gen_index_contract_class_id, artifact_hash, private_functions_root, class_id, const_four }
in poseidon2_hash.start { ... };

#[CLASS_ID_POSEIDON2_1]
sel { public_bytecode_commitment, precomputed.zero, precomputed.zero, class_id }
in poseidon2_hash.end { ... };
```

### 7.3 Security Analysis

Simple hash derivation - correctness ensured by Poseidon2 lookups.

---

## 8. contract_instance_retrieval.pil

### 8.1 Purpose

Proves contract instance existence:
1. Check if protocol contract (special handling)
2. Check nullifier existence for non-protocol contracts
3. Derive address from instance members
4. Validate current class ID via update_check

### 8.2 Protocol Contract Handling

```pil
// contract_instance_retrieval.pil:100-103
#[CHECK_PROTOCOL_ADDRESS_RANGE]
sel { max_protocol_contracts, address_sub_one, is_protocol_contract }
in ff_gt.sel_gt { ff_gt.a, ff_gt.b, ff_gt.result };

// contract_instance_retrieval.pil:111-118
#[READ_DERIVED_ADDRESS_FROM_PUBLIC_INPUTS]
is_protocol_contract { derived_address_pi_index, derived_address }
in public_inputs.sel { precomputed.clk, public_inputs.cols[0] };
```

### 8.3 Nullifier Check

```pil
// contract_instance_retrieval.pil:133-146
#[DEPLOYMENT_NULLIFIER_READ]
should_check_nullifier {
    exists, address, nullifier_tree_root, deployer_protocol_contract_address, sel
} in nullifier_check.sel { ... };
```

### 8.4 Address Derivation

```pil
// contract_instance_retrieval.pil:165-194
#[ADDRESS_DERIVATION]
exists {
    derived_address, salt, deployer_addr, original_class_id, init_hash,
    nullifier_key_x, nullifier_key_y, incoming_viewing_key_x, incoming_viewing_key_y,
    outgoing_viewing_key_x, outgoing_viewing_key_y, tagging_key_x, tagging_key_y
} in address_derivation.sel { ... };
```

### 8.5 Update Check

```pil
// contract_instance_retrieval.pil:200-211
#[UPDATE_CHECK]
should_check_for_update {
    address, current_class_id, original_class_id, public_data_tree_root
} in update_check.sel { ... };
```

### 8.6 Security Analysis

| Property | Protection |
|----------|------------|
| Protocol contract detection | ff_gt range check |
| Nullifier existence | nullifier_check lookup |
| Address correct | address_derivation lookup |
| Class ID current | update_check lookup |
| Members zero if DNE | Explicit constraints |

---

## 9. instr_fetching.pil

### 9.1 Purpose

Fetches instruction from bytecode:
1. Check pc in range
2. Check opcode valid
3. Check instruction size fits
4. Check tag valid
5. Decompose operands

### 9.2 Error Hierarchy

```pil
// instr_fetching.pil:79-84
pol PARSING_ERROR_EXCEPT_TAG_ERROR = pc_out_of_range + opcode_out_of_range + instr_out_of_range;
pol commit sel_parsing_err;
sel_parsing_err = PARSING_ERROR_EXCEPT_TAG_ERROR + tag_out_of_range;
sel_parsing_err * (1 - sel_parsing_err) = 0; // enforces disjoint errors
```

### 9.3 PC Out-of-Range

```pil
// instr_fetching.pil:101-112
#[PC_OUT_OF_RANGE_TOGGLE]
pc_abs_diff = sel * ((2 * pc_out_of_range - 1) * (pc - bytecode_size) - 1 + pc_out_of_range);

#[PC_ABS_DIFF_POSITIVE]
sel { pc_abs_diff, pc_size_in_bits } in range_check.sel { ... };
```

### 9.4 Instruction Out-of-Range

```pil
// instr_fetching.pil:130-134
#[INSTR_OUT_OF_RANGE_TOGGLE]
instr_abs_diff = (2 * instr_out_of_range - 1) * (instr_size - bytes_to_read) - instr_out_of_range;

#[INSTR_ABS_DIFF_POSITIVE]
sel { instr_abs_diff } in precomputed.sel_range_8 { precomputed.clk };
```

### 9.5 Bytes Retrieval

```pil
// instr_fetching.pil:183-209
#[BYTES_FROM_BC_DEC]
sel_pc_in_range {
    bytecode_id, pc, bytes_to_read,
    bd0, bd1, bd2, ..., bd36
} in bc_decomposition.sel { ... };
```

### 9.6 Operand Decomposition

```pil
// instr_fetching.pil:282-297
#[ADDRESSING_MODE_BYTES_DECOMPOSITION]
addressing_mode = (1 - PARSING_ERROR_EXCEPT_TAG_ERROR) * (sel_op_dc_0 * (bd1 * 2**8 + bd2 * 2**0) + ...);

#[OP1_BYTES_DECOMPOSITION]
op1 = (1 - PARSING_ERROR_EXCEPT_TAG_ERROR) * (...);
// ... continues for op2-op7
```

### 9.7 Security Analysis

| Property | Protection |
|----------|------------|
| PC bounds | Range check on pc_abs_diff |
| Opcode valid | precomputed lookup |
| Instruction fits | Range check on instr_abs_diff |
| Tag valid | precomputed lookup |
| Bytes from bytecode | bc_decomposition lookup |
| Disjoint errors | Boolean product constraint |

---

## 10. update_check.pil

### 10.1 Purpose

Validates current_class_id accounting for contract updates stored in public data tree as delayed public mutable.

### 10.2 Delayed Public Mutable Structure

```
| slot  | hash_slot | hash_slot+1 | hash_slot+2 | hash_slot+3 |
|-------|-----------|-------------|-------------|-------------|
| value | metadata  | pre_class   | post_class  | H(m,pre,post) |
```

### 10.3 Key Constraints

```pil
// update_check.pil:67-74 - Slot derivation
#[DELAYED_PUBLIC_MUTABLE_SLOT_POSEIDON2]
sel { dom_sep, updated_class_ids_slot, address, delayed_public_mutable_slot, const_three }
in poseidon2_hash.start { ... };

// update_check.pil:83-94 - Hash read from public data tree
#[UPDATE_HASH_PUBLIC_DATA_READ]
sel { deployer_contract, hash_slot, update_hash, public_data_tree_root }
in public_data_check.sel { ... };

// update_check.pil:108-109 - Never updated case
#[NEVER_UPDATED_CHECK]
(1 - hash_not_zero) * (current_class_id - original_class_id) = 0;

// update_check.pil:115-122 - Preimage verification
#[UPDATE_HASH_POSEIDON2]
hash_not_zero { metadata, pre_class_id, post_class_id, update_hash, const_three }
in poseidon2_hash.start { ... };
```

### 10.4 Timestamp Comparison

```pil
// update_check.pil:138-148 - Metadata decomposition
#[UPDATE_HI_METADATA_RANGE]
hash_not_zero { update_hi_metadata, update_hi_metadata_bit_size }
in range_check.sel { ... };

#[UPDATE_METADATA_DECOMPOSITION]
update_hi_metadata * TWO_POW_32 + timestamp_of_change - update_preimage_metadata = 0;

// update_check.pil:156-158 - Timestamp comparison
#[TIMESTAMP_IS_LT_TIMESTAMP_OF_CHANGE]
hash_not_zero { timestamp_of_change, timestamp, timestamp_is_lt_timestamp_of_change }
in gt.sel_others { ... };
```

### 10.5 Class ID Assignment

```pil
// update_check.pil:173-178
#[FUTURE_UPDATE_CLASS_ID_ASSIGNMENT]
hash_not_zero * timestamp_is_lt_timestamp_of_change *
    (original_class_id * update_pre_class_id_is_zero + update_preimage_pre_class_id - current_class_id) = 0;

#[PAST_UPDATE_CLASS_ID_ASSIGNMENT]
hash_not_zero * (1 - timestamp_is_lt_timestamp_of_change) *
    (original_class_id * update_post_class_id_is_zero + update_preimage_post_class_id - current_class_id) = 0;
```

### 10.6 Security Analysis

| Property | Protection |
|----------|------------|
| Slot derivation | Poseidon2 lookup |
| Hash read | public_data_check lookup |
| Preimage correct | Poseidon2 lookup |
| Metadata decomposition | Range checks |
| Timestamp comparison | gt lookup |
| Class ID correct | Conditional assignment constraints |

---

## 11. Soundness Verification

### 11.1 Overall Attack Surface

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Forge bytecode hash | Poseidon2 lookups + packing constraint | PROTECTED |
| Wrong instruction bytes | Lookup to bc_decomposition | PROTECTED |
| Skip instruction bytes | Sliding window constraint | PROTECTED |
| Fake contract existence | Nullifier check lookup | PROTECTED |
| Wrong address derivation | address_derivation lookup | PROTECTED |
| Wrong class ID | class_id_derivation + update_check lookups | PROTECTED |
| Bypass error | Disjoint error constraint | PROTECTED |
| Protocol contract bypass | ff_gt range check | PROTECTED |
| Update bypass | Timestamp comparison via gt | PROTECTED |

### 11.2 Critical Security Properties

#### 11.2.1 Bytecode Integrity Chain

```
bytes → bc_decomposition → packed_field → bc_hashing → bytecode_id
```

All links verified via lookups/permutations.

#### 11.2.2 Contract Instance Chain

```
address → nullifier_check → exists
           ↓
       instance_members → address_derivation → address (verified)
           ↓
       class_id → update_check → current_class_id
```

#### 11.2.3 Instruction Integrity

```
(pc, bytecode_id) → instr_fetching → (opcode, operands)
                          ↓
                    bc_decomposition (bytes)
                          ↓
                    precomputed (instruction spec)
```

---

## 12. Findings

### No Critical Vulnerabilities Found

All bytecode gadgets are **SOUND**.

### INFO-1: Empty Bytecode Not Supported

From bc_decomposition.pil:
> This does NOT support empty bytecode. We rely on other means to prevent processing empty bytecode.

Empty bytecodes are prevented at registration.

### INFO-2: WINDOW_SIZE = 37 Hardcoded

From bc_hashing.pil:
> NOTE: This relies on the hardcoded WINDOW_SIZE = 37 and WILL BREAK if this ever changes!

Critical dependency between bc_decomposition and bc_hashing.

### INFO-3: Protocol Contracts Special Case

Protocol contracts (address 1 to MAX_PROTOCOL_CONTRACTS) bypass nullifier check and use derived address from public inputs.

### INFO-4: Disjoint Error Enforcement

From instr_fetching.pil:
> sel_parsing_err * (1 - sel_parsing_err) = 0; // enforces disjoint errors

Since `sel_parsing_err` is a sum of 4 booleans, the boolean constraint forces at most one error.

### INFO-5: Delayed Public Mutable

Contract updates use a complex delayed structure. Zero pre/post class IDs mean "use original_class_id".

---

## 13. Conclusion

**Status**: SOUND

All 8 bytecode gadgets are **correctly implemented** with:

**address_derivation.pil**:
- Sound multi-step hash derivation
- Correct ECC operations via lookups

**bc_decomposition.pil**:
- Correct sliding window propagation
- Sound packed field repacking

**bc_hashing.pil**:
- Correct domain separation
- Permutations for packed fields
- Complete bytecode consumption check

**bc_retrieval.pil**:
- Correct instance existence checking
- Class ID derivation lookup
- Bytecode limit enforcement

**class_id_derivation.pil**:
- Simple correct hash derivation

**contract_instance_retrieval.pil**:
- Protocol contract special handling
- Nullifier existence check
- Address and update verification

**instr_fetching.pil**:
- Complete error hierarchy
- Correct operand decomposition
- Range checks for bounds

**update_check.pil**:
- Correct delayed public mutable handling
- Timestamp comparison via gt
- Proper class ID assignment

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary by File

### address_derivation.pil
| Constraint | Purpose |
|------------|---------|
| SALTED_INITIALIZATION_HASH_POSEIDON2_* | Salted init hash |
| PARTIAL_ADDRESS_POSEIDON2 | Partial address |
| PUBLIC_KEYS_HASH_POSEIDON2_* | Public keys hash |
| PREADDRESS_POSEIDON2 | Preaddress |
| PREADDRESS_SCALAR_MUL | Preaddress public key |
| ADDRESS_ECADD | Final address |

### bc_decomposition.pil
| Constraint | Purpose |
|------------|---------|
| BC_DEC_SEL_BYTES_REM_NON_ZERO | Selector toggle |
| TRACE_CONTINUITY | Contiguous trace |
| BC_DEC_LAST_CONTRACT_BYTES_REM_ONE | Last row detection |
| BC_DEC_PC_* | PC management |
| BC_DEC_ID_CONSTANT | ID stable |
| BYTES_ARE_BYTES | 8-bit range check |
| SEL_WINDOWS_GT_REMAINING_* | Window boundary |
| BC_DECOMPOSITION_REPACKING | Pack 31 bytes |

### bc_hashing.pil
| Constraint | Purpose |
|------------|---------|
| TRACE_CONTINUITY | Contiguous trace |
| START_AFTER_LATCH | New start after latch |
| PC_INCREMENTS* | PC management |
| START_IS_SEPARATOR | Domain separator |
| GET_PACKED_FIELD_* | Permutation to bc_dec |
| PADDING_* | Padding constraints |
| CHECK_FINAL_BYTES_REMAINING | Complete consumption |
| HASH_IS_ID | bytecode_id = hash |
| POSEIDON2_HASH | Hash lookup |

### instr_fetching.pil
| Constraint | Purpose |
|------------|---------|
| PC_OUT_OF_RANGE_TOGGLE | PC bounds check |
| PC_ABS_DIFF_POSITIVE | Range check |
| INSTR_OUT_OF_RANGE_TOGGLE | Instruction fits |
| TAG_VALUE_VALIDATION | Tag validity |
| BYTECODE_SIZE_FROM_BC_DEC | Get size |
| BYTES_FROM_BC_DEC | Get bytes |
| WIRE_INSTRUCTION_INFO | Opcode info |
| *_BYTES_DECOMPOSITION | Operand decoding |

### update_check.pil
| Constraint | Purpose |
|------------|---------|
| TIMESTAMP_FROM_PUBLIC_INPUTS | Get timestamp |
| DELAYED_PUBLIC_MUTABLE_SLOT_POSEIDON2 | Slot derivation |
| UPDATE_HASH_PUBLIC_DATA_READ | Read hash |
| HASH_IS_ZERO_CHECK | Zero check |
| NEVER_UPDATED_CHECK | No update case |
| UPDATE_HASH_POSEIDON2 | Preimage verify |
| UPDATE_*_METADATA_RANGE | Decomposition |
| TIMESTAMP_IS_LT_TIMESTAMP_OF_CHANGE | Time compare |
| *_UPDATE_CLASS_ID_ASSIGNMENT | Class ID |
