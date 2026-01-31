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
| ✅ Audited | 26 |
| ⚪ N/A | 2 |
| ⏳ Pending | 37 |
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
- [x] `to_radix_mem.pil` - ✅ Audited (see TO_RADIX_MEM_SECURITY_AUDIT.md)

### Memory
- [x] `memory.pil` - ✅ Audited (see MEMORY_SECURITY_AUDIT.md)
- [x] `data_copy.pil` - ✅ Audited (see DATA_COPY_SECURITY_AUDIT.md)

### Cryptographic Primitives
- [x] `poseidon2_hash.pil` - ✅ Audited (see POSEIDON2_HASH_SECURITY_AUDIT.md)
- [ ] `poseidon2_mem.pil` - ⏳ Pending
- [ ] `poseidon2_params.pil` - ⏳ Pending
- [ ] `poseidon2_perm.pil` - ⏳ Pending
- [x] `sha256.pil` - ✅ Audited (see SHA256_SECURITY_AUDIT.md)
- [x] `sha256_mem.pil` - ✅ Audited (see SHA256_MEM_SECURITY_AUDIT.md)
- [x] `keccakf1600.pil` - ✅ Audited (see KECCAKF1600_SECURITY_AUDIT.md)
- [x] `keccak_memory.pil` - ✅ Audited (see KECCAK_MEMORY_SECURITY_AUDIT.md)

### Elliptic Curve
- [x] `ecc.pil` - ✅ Audited (see ECC_SECURITY_AUDIT.md)
- [x] `ecc_mem.pil` - ✅ Audited (see ECC_MEM_SECURITY_AUDIT.md)
- [x] `scalar_mul.pil` - ✅ Audited (see SCALAR_MUL_SECURITY_AUDIT.md)

### Execution
- [ ] `execution.pil` - ⏳ Pending
- [ ] `execution/addressing.pil` - ⏳ Pending
- [ ] `execution/discard.pil` - ⏳ Pending
- [ ] `execution/gas.pil` - ⏳ Pending
- [ ] `execution/registers.pil` - ⏳ Pending

### Context & Stack
- [x] `context.pil` - ✅ Audited (see CONTEXT_SECURITY_AUDIT.md)
- [x] `context_stack.pil` - ✅ Audited (see CONTEXT_STACK_SECURITY_AUDIT.md)
- [x] `internal_call_stack.pil` - ✅ Audited (see INTERNAL_CALL_STACK_SECURITY_AUDIT.md)

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
- [x] `calldata.pil` - ✅ Audited (see CALLDATA_SECURITY_AUDIT.md)
- [x] `calldata_hashing.pil` - ✅ Audited (see CALLDATA_HASHING_SECURITY_AUDIT.md)

### Transaction
- [x] `tx.pil` - ✅ Audited (see TX_SECURITY_AUDIT.md)
- [x] `tx_context.pil` - ✅ Audited (see TX_SECURITY_AUDIT.md, virtual to tx.pil)
- [x] `tx_discard.pil` - ✅ Audited (see TX_SECURITY_AUDIT.md, virtual to tx.pil)
- [x] `public_inputs.pil` - ⚪ N/A (see PUBLIC_INPUTS_SECURITY_AUDIT.md)

### Trees (Merkle Proofs)
- [x] `trees/merkle_check.pil` - ✅ Audited (see MERKLE_CHECK_SECURITY_AUDIT.md)
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
- [x] `precomputed.pil` - ⚪ N/A (see PRECOMPUTED_SECURITY_AUDIT.md)
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

### 8. merkle_check.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [MERKLE_CHECK_SECURITY_AUDIT.md](./MERKLE_CHECK_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - INFO-1: Write selector usage warning documented

### 9. sha256.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [SHA256_SECURITY_AUDIT.md](./SHA256_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - Depends on bitwise gadget (ghost row fix critical)

### 10. keccakf1600.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [KECCAKF1600_SECURITY_AUDIT.md](./KECCAKF1600_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - 100+ bitwise lookups per round (depends on ghost row fix)

### 11. ecc.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [ECC_SECURITY_AUDIT.md](./ECC_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - INFO-1: No on-curve verification (caller responsibility)

### 12. scalar_mul.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [SCALAR_MUL_SECURITY_AUDIT.md](./SCALAR_MUL_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - Fixed 254 rows per operation

### 13. data_copy.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [DATA_COPY_SECURITY_AUDIT.md](./DATA_COPY_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - Uses permutation for secure memory integration

### 14. context.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [CONTEXT_SECURITY_AUDIT.md](./CONTEXT_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - Large virtual gadget (40+ columns)

### 15. context_stack.pil
- **Date**: 2024
- **Status**: ✅ SOUND (N/A - Storage Only)
- **Report**: [CONTEXT_STACK_SECURITY_AUDIT.md](./CONTEXT_STACK_SECURITY_AUDIT.md)
- **Findings**:
  - Storage-only gadget, no logic vulnerabilities possible

### 16. internal_call_stack.pil
- **Date**: 2024
- **Status**: ✅ SOUND (N/A - Storage Only)
- **Report**: [INTERNAL_CALL_STACK_SECURITY_AUDIT.md](./INTERNAL_CALL_STACK_SECURITY_AUDIT.md)
- **Findings**:
  - Storage-only gadget, no logic vulnerabilities possible

### 17. calldata.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [CALLDATA_SECURITY_AUDIT.md](./CALLDATA_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - INFO-1: Values are hints, verified by calldata_hashing

### 18. sha256_mem.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [SHA256_MEM_SECURITY_AUDIT.md](./SHA256_MEM_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - Batched tag checking using powers of 2
  - Memory column reuse between reads and writes

### 19. keccak_memory.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [KECCAK_MEMORY_SECURITY_AUDIT.md](./KECCAK_MEMORY_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - Multi-row value shifting for horizontal access
  - Early termination on tag error

### 20. ecc_mem.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [ECC_MEM_SECURITY_AUDIT.md](./ECC_MEM_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - On-curve verification (Y^2 = X^3 - 17)
  - Infinity point remapping to (0, 0)

### 21. to_radix_mem.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [TO_RADIX_MEM_SECURITY_AUDIT.md](./TO_RADIX_MEM_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - Big-endian reversal of little-endian core output
  - Ghost row protection for memory writes

### 22. poseidon2_hash.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [POSEIDON2_HASH_SECURITY_AUDIT.md](./POSEIDON2_HASH_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - IV = 2^64 * input_len for domain separation
  - Padding not enforced to zero (caller responsibility)

### 23. calldata_hashing.pil
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [CALLDATA_HASHING_SECURITY_AUDIT.md](./CALLDATA_HASHING_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - Domain separator prepended
  - Padding enforced to zero

### 24. tx.pil (+ tx_context.pil + tx_discard.pil)
- **Date**: 2024
- **Status**: ✅ SOUND
- **Report**: [TX_SECURITY_AUDIT.md](./TX_SECURITY_AUDIT.md)
- **Findings**:
  - No vulnerabilities found
  - 12 phases with proper sequencing
  - Revert handling with state restoration
  - Discard flag propagation

### 25. public_inputs.pil
- **Date**: 2024
- **Status**: ⚪ N/A (Infrastructure Only)
- **Report**: [PUBLIC_INPUTS_SECURITY_AUDIT.md](./PUBLIC_INPUTS_SECURITY_AUDIT.md)
- **Findings**:
  - No constraints to audit, declarations only

### 26. precomputed.pil
- **Date**: 2024
- **Status**: ⚪ N/A (Constants Only)
- **Report**: [PRECOMPUTED_SECURITY_AUDIT.md](./PRECOMPUTED_SECURITY_AUDIT.md)
- **Findings**:
  - No constraints to audit, constant declarations only

---

## Audit Priority

### Critical Priority (Core Security)
1. ~~`memory.pil`~~ - ✅ COMPLETE
2. ~~`ff_gt.pil`~~ - ✅ COMPLETE
3. ~~`alu.pil`~~ - ✅ COMPLETE
4. ~~`trees/merkle_check.pil`~~ - ✅ COMPLETE
5. `execution.pil` - Main execution logic

### High Priority (Cryptographic)
1. `poseidon2_perm.pil` - Hash function core (large file)
2. ~~`sha256.pil`~~ - ✅ COMPLETE
3. ~~`keccakf1600.pil`~~ - ✅ COMPLETE
4. ~~`ecc.pil`~~ - ✅ COMPLETE

### Medium Priority (Opcodes & Integration)
1. All `opcodes/*.pil` files
2. All `trees/*.pil` files
3. `bytecode/*.pil` files

---

## Notes

- Audits follow the methodology in [PIL_AUDIT_METHODOLOGY.md](./PIL_AUDIT_METHODOLOGY.md)
- Each audit produces a detailed report in a separate markdown file
- All findings are categorized as CRITICAL, HIGH, MEDIUM, LOW, or INFO
