# PIL Security Audit Tracker

This document tracks the security audit status of all PIL gadgets in the AVM2 codebase.

**Legend:**
- ✅ Audited - Complete security audit performed
- 🔄 In Progress - Currently being audited
- ⏳ Pending - Not yet audited
- ⚪ N/A - Not applicable (e.g., constants, includes only)

---

## Audit Summary

| Status | Count |
|--------|-------|
| ✅ Audited | 7 |
| ⏳ Pending | 58 |
| **Total** | **65** |

---

## Core Gadgets

### Arithmetic & Comparison
- [x] `range_check.pil` - ✅ Audited (see RANGE_CHECK_SECURITY_AUDIT.md)
- [x] `gt.pil` - ✅ Audited (see GT_SECURITY_AUDIT.md)
- [x] `ff_gt.pil` - ✅ Audited (see FF_GT_SECURITY_AUDIT.md)
- [x] `alu.pil` - ✅ Audited (see ALU_SECURITY_AUDIT.md)
- [x] `bitwise.pil` - ✅ Audited (see BITWISE_SECURITY_AUDIT.md)
- [x] `to_radix.pil` - ✅ Audited (see TO_RADIX_SECURITY_AUDIT.md)
- [ ] `to_radix_mem.pil` - ⏳ Pending

### Memory
- [x] `memory.pil` - ✅ Audited (see MEMORY_SECURITY_AUDIT.md)
- [ ] `data_copy.pil` - ⏳ Pending

### Cryptographic Primitives
- [ ] `poseidon2_hash.pil` - ⏳ Pending
- [ ] `poseidon2_mem.pil` - ⏳ Pending
- [ ] `poseidon2_params.pil` - ⏳ Pending
- [ ] `poseidon2_perm.pil` - ⏳ Pending
- [ ] `sha256.pil` - ⏳ Pending
- [ ] `sha256_mem.pil` - ⏳ Pending
- [ ] `keccakf1600.pil` - ⏳ Pending
- [ ] `keccak_memory.pil` - ⏳ Pending

### Elliptic Curve
- [ ] `ecc.pil` - ⏳ Pending
- [ ] `ecc_mem.pil` - ⏳ Pending
- [ ] `scalar_mul.pil` - ⏳ Pending

### Execution
- [ ] `execution.pil` - ⏳ Pending
- [ ] `execution/addressing.pil` - ⏳ Pending
- [ ] `execution/discard.pil` - ⏳ Pending
- [ ] `execution/gas.pil` - ⏳ Pending
- [ ] `execution/registers.pil` - ⏳ Pending

### Context & Stack
- [ ] `context.pil` - ⏳ Pending
- [ ] `context_stack.pil` - ⏳ Pending
- [ ] `internal_call_stack.pil` - ⏳ Pending

### Bytecode
- [ ] `bytecode/address_derivation.pil` - ⏳ Pending
- [ ] `bytecode/bc_decomposition.pil` - ⏳ Pending
- [ ] `bytecode/bc_hashing.pil` - ⏳ Pending
- [ ] `bytecode/bc_retrieval.pil` - ⏳ Pending
- [ ] `bytecode/class_id_derivation.pil` - ⏳ Pending
- [ ] `bytecode/contract_instance_retrieval.pil` - ⏳ Pending
- [ ] `bytecode/instr_fetching.pil` - ⏳ Pending
- [ ] `bytecode/update_check.pil` - ⏳ Pending

### Calldata
- [ ] `calldata.pil` - ⏳ Pending
- [ ] `calldata_hashing.pil` - ⏳ Pending

### Transaction
- [ ] `tx.pil` - ⏳ Pending
- [ ] `tx_context.pil` - ⏳ Pending
- [ ] `tx_discard.pil` - ⏳ Pending
- [ ] `public_inputs.pil` - ⏳ Pending

### Trees (Merkle Proofs)
- [ ] `trees/merkle_check.pil` - ⏳ Pending
- [ ] `trees/l1_to_l2_message_tree_check.pil` - ⏳ Pending
- [ ] `trees/note_hash_tree_check.pil` - ⏳ Pending
- [ ] `trees/nullifier_check.pil` - ⏳ Pending
- [ ] `trees/public_data_check.pil` - ⏳ Pending
- [ ] `trees/public_data_squash.pil` - ⏳ Pending
- [ ] `trees/retrieved_bytecodes_tree_check.pil` - ⏳ Pending
- [ ] `trees/written_public_data_slots_tree_check.pil` - ⏳ Pending

### Opcodes
- [ ] `opcodes/emit_notehash.pil` - ⏳ Pending
- [ ] `opcodes/emit_nullifier.pil` - ⏳ Pending
- [ ] `opcodes/emit_unencrypted_log.pil` - ⏳ Pending
- [ ] `opcodes/external_call.pil` - ⏳ Pending
- [ ] `opcodes/get_contract_instance.pil` - ⏳ Pending
- [ ] `opcodes/get_env_var.pil` - ⏳ Pending
- [ ] `opcodes/internal_call.pil` - ⏳ Pending
- [ ] `opcodes/l1_to_l2_message_exists.pil` - ⏳ Pending
- [ ] `opcodes/notehash_exists.pil` - ⏳ Pending
- [ ] `opcodes/nullifier_exists.pil` - ⏳ Pending
- [ ] `opcodes/send_l2_to_l1_msg.pil` - ⏳ Pending
- [ ] `opcodes/sload.pil` - ⏳ Pending
- [ ] `opcodes/sstore.pil` - ⏳ Pending

### Infrastructure
- [ ] `precomputed.pil` - ⏳ Pending
- [ ] `constants_gen.pil` - ⏳ Pending (may be N/A - constants only)

---

## Completed Audits

### 1. range_check.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [RANGE_CHECK_SECURITY_AUDIT.md](./RANGE_CHECK_SECURITY_AUDIT.md)
- **Findings**:
  - LOW-1: Uninitialized array in trace generation (no impact)
  - INFO-1: Fuzzer doesn't test num_bits=0

### 2. gt.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [GT_SECURITY_AUDIT.md](./GT_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - All callers satisfy preconditions

### 3. ff_gt.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [FF_GT_SECURITY_AUDIT.md](./FF_GT_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - Multi-row operation (5 rows for GT, 2 for DEC)
  - Proper canonical representation checks

### 4. memory.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [MEMORY_SECURITY_AUDIT.md](./MEMORY_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - INFO-1: Large permutation selector sum (36+ selectors)

### 5. bitwise.pil
- **Date**: 2024
- **Status**: ✅ SOUND (after fix)
- **Report**: [BITWISE_SECURITY_AUDIT.md](./BITWISE_SECURITY_AUDIT.md)
- **Findings**:
  - FIXED: Ghost row XOR forgery vulnerability (PR #19875)
  - Critical fix: `(start_keccak + start_sha256) * (1 - sel) = 0`

### 6. to_radix.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [TO_RADIX_SECURITY_AUDIT.md](./TO_RADIX_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - Proper overflow protection against field modulus
  - Ghost row protection in memory variant

### 7. alu.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [ALU_SECURITY_AUDIT.md](./ALU_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - Comprehensive error handling
  - Proper integration with range_check, gt, ff_gt gadgets

---

## Audit Priority

### Critical Priority (Core Security)
1. ~~`memory.pil`~~ - ✅ COMPLETE
2. ~~`ff_gt.pil`~~ - ✅ COMPLETE
3. ~~`alu.pil`~~ - ✅ COMPLETE
4. `trees/merkle_check.pil` - Merkle proof verification
5. `execution.pil` - Main execution logic

### High Priority (Cryptographic)
1. `poseidon2_perm.pil` - Hash function core (large file)
2. `sha256.pil` - SHA256 implementation
3. `keccakf1600.pil` - Keccak permutation
4. `ecc.pil` - Elliptic curve operations

### Medium Priority (Opcodes & Integration)
1. All `opcodes/*.pil` files
2. All `trees/*.pil` files
3. `bytecode/*.pil` files

---

## Notes

- Audits follow the methodology in [PIL_AUDIT_METHODOLOGY.md](./PIL_AUDIT_METHODOLOGY.md)
- Each audit produces a detailed report in a separate markdown file
- All findings are categorized as CRITICAL, HIGH, MEDIUM, LOW, or INFO
