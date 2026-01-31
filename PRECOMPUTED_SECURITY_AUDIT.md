# Security Audit: precomputed.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: N/A (Constants Only)

---

## 1. Overview

The `precomputed.pil` file defines all precomputed constant columns used throughout the AVM circuit. These columns are populated at circuit compilation time and cannot be modified by the prover.

### Key Characteristics
- 80+ constant column declarations
- No committed (prover) columns
- No constraint logic
- Lookup tables for various operations

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/precomputed.pil` | Constant column declarations (184 lines) |

---

## 3. Column Categories

### 3.1 General Infrastructure
- `clk`: Row counter (0 to circuit size)
- `zero`: Column of zeros
- `first_row`: 1 only at row 0

### 3.2 Bitwise Operations
- `sel_bitwise`: Selector for bitwise table (first 3*256 rows)
- `bitwise_op_id`: AND/OR/XOR identifier
- `bitwise_input_a`, `bitwise_input_b`: 8-bit inputs
- `bitwise_output`: Result of operation

### 3.3 Range Checks
- `sel_range_8`: 1 in first 2^8 rows
- `sel_range_16`: 1 in first 2^16 rows

### 3.4 Power of 2 Table
- `power_of_2`: 2^clk for first 256 rows

### 3.5 SHA256 Constants
- `sel_sha256_compression`: Selector
- `sha256_compression_round_constant`: K values

### 3.6 Memory Tag Parameters
- `sel_tag_parameters`: Selector for tag rows
- `tag_byte_length`, `tag_max_bits`, `tag_max_value`

### 3.7 Wire Instruction Spec
- `sel_op_dc_*`: Operand decomposition selectors
- `exec_opcode`: Execution opcode mapping
- `instr_size`: Instruction size in bytes
- `sel_has_tag`, `sel_tag_is_op2`: Tag handling flags

### 3.8 Execution Instruction Spec
- `sel_exec_spec`: Selector
- `exec_opcode_*_gas`: Gas costs
- `sel_mem_op_reg[]`, `rw_reg[]`: Memory access patterns
- `subtrace_id`, `subtrace_operation_id`: Gadget dispatch

### 3.9 TX Phase Table
- `sel_phase`: Selector for phase rows
- `is_public_call_request`, `is_teardown`, etc.: Phase attributes
- `next_phase_on_revert`: Revert target phase

### 3.10 Keccak Constants
- `sel_keccak`: Selector for rounds 1-24
- `keccak_round_constant`: 24 round constants

### 3.11 Radix Decomposition
- `sel_to_radix_p_limb_counts`: Selector
- `to_radix_safe_limbs`: Safe limb count per radix
- `sel_p_decomposition`: P decomposition table

### 3.12 Environment Variable Lookup
- `invalid_envvar_enum`: Invalid enum detection
- `envvar_pi_row_idx`: Public input row mapping
- Various environment variable selectors

### 3.13 Contract Instance Lookup
- `is_valid_member_enum`: Valid member detection
- `is_deployer`, `is_class_id`, `is_init_hash`: Member selectors

---

## 4. Soundness Analysis

### 4.1 No Constraints to Audit

This file contains only `pol constant` declarations. All columns are:
- Populated at compile time
- Immutable during proving
- Not controllable by malicious provers

### 4.2 Security Depends On

1. **Correct Population**: Trace generation must populate these correctly
2. **Correct Usage**: Callers must use appropriate selectors
3. **Table Completeness**: Tables must cover all valid inputs

### 4.3 Critical Tables

The following tables are security-critical:
- **Phase table**: Defines valid phase transitions
- **Instruction spec**: Defines valid opcodes and gas costs
- **P decomposition**: Used for overflow protection in to_radix

---

## 5. Findings

### N/A - Constants Only

No vulnerabilities possible in this file as it contains only constant declarations.

### INFO-1: Table Population

The security of lookups into these tables depends on:
1. Tables being correctly populated by the trace generator
2. Tables covering exactly the valid input space
3. Selectors being active only on valid table rows

---

## 6. Conclusion

**Status**: N/A (Constants Only)

The precomputed.pil file defines infrastructure for constant lookup tables. It contains no constraint logic and cannot introduce soundness vulnerabilities. The security of operations using these tables depends on correct population and usage by other gadgets.

---

## Appendix: Column Summary

| Category | Columns | Rows |
|----------|---------|------|
| Bitwise | 5 | 3 * 256 = 768 |
| Range check | 2 | 2^16 |
| Power of 2 | 1 | 256 |
| Tag parameters | 4 | 7 |
| SHA256 | 2 | 64 |
| Wire spec | 22 | 256 |
| Exec spec | 30+ | ~100 |
| Phase | 16 | 12 |
| Keccak | 2 | 24 |
| Radix | 6 | varies |
| EnvVar | 10 | varies |
| Contract | 4 | varies |
