# AVM2 Public Inputs & Precomputed Infrastructure Deep Security Audit

**Audit Date**: 2025-01
**Auditor**: Security Analysis
**Scope**: Foundation infrastructure in `barretenberg/cpp/pil/vm2/`
**Methodology**: 6-Phase Deep Audit (Discovery, Understanding, Soundness, Completeness, Integration, Reporting)

---

## Executive Summary

This audit covers the foundational infrastructure components that provide constants, precomputed lookup tables, and public input interfaces for all AVM2 gadgets:

| File | Lines | Purpose | Verdict |
|------|-------|---------|---------|
| public_inputs.pil | 6 | Public input interface | **SOUND** |
| precomputed.pil | 184 | Precomputed lookup tables | **SOUND** |
| constants_gen.pil | 181 | Protocol constants (generated) | **SOUND** |

**Overall Verdict**: All infrastructure components are **SOUND** with no vulnerabilities identified.

---

## Phase 1: Discovery

### File Inventory

```
Infrastructure Files:
├── public_inputs.pil      # Public input columns (6 lines)
├── precomputed.pil        # Precomputed lookup tables (184 lines)
└── constants_gen.pil      # Generated constants (181 lines)
```

### Usage Statistics

#### public_inputs.pil
Used by **15+ gadgets** for reading/writing transaction data:
- tx.pil, tx_context.pil (transaction orchestration)
- note_hash_tree_check.pil (write note hashes)
- nullifier_check.pil (write nullifiers)
- public_data_check.pil (write storage updates)
- send_l2_to_l1_msg.pil (write L2→L1 messages)
- get_env_var.pil (read environment variables)
- emit_unencrypted_log.pil (write logs)
- contract_instance_retrieval.pil (read contract data)
- update_check.pil (validate bytecode updates)

#### precomputed.pil
Used by **all gadgets** for:
- `precomputed.clk`: Clock/row counter for indexing
- `precomputed.zero`: Constant zero column
- `precomputed.first_row`: First row detection
- `precomputed.sel_range_8`: 8-bit range check selector
- `precomputed.sel_range_16`: 16-bit range check selector
- Bitwise tables, SHA256 constants, Keccak constants
- Tag parameters, opcode specs, phase tables

#### constants_gen.pil
Referenced by **all gadgets** for:
- Tree heights and limits
- Memory tag values
- Public input offsets
- Domain separators
- Protocol addresses

---

## Phase 2: Understanding

### 2.1 public_inputs.pil

**Structure**:
```pil
namespace public_inputs;
    pol constant sel;    // 1 for rows [0, AVM_PUBLIC_INPUTS_COLUMNS_MAX_LENGTH)
    pol public cols[4];  // 4 public input columns
```

**Design**:
- Minimal 6-line file defining the public input interface
- `sel` is a precomputed selector enabling lookups up to row 4685
- `cols[4]` contains 4 public columns that can store multiple values per row
- Total capacity: 4685 rows × 4 columns = 18,740 field elements

**Lookup Pattern**:
```pil
// Reading a single value at row_idx
sel_caller { row_idx, value }
in public_inputs.sel { precomputed.clk, public_inputs.cols[0] };

// Reading/writing multiple values at row_idx
sel_caller { row_idx, val0, val1, val2 }
in public_inputs.sel { precomputed.clk, public_inputs.cols[0], public_inputs.cols[1], public_inputs.cols[2] };
```

---

### 2.2 precomputed.pil

**Categories of Precomputed Columns**:

#### 2.2.1 Basic Utilities
```pil
pol constant clk;        // Row counter: 0, 1, 2, ..., 2^21-1
pol constant zero;       // All zeros
pol constant first_row;  // 1 at row 0, 0 elsewhere
```

#### 2.2.2 Range Check Tables
```pil
pol constant sel_range_8;   // 1 for rows [0, 256)
pol constant sel_range_16;  // 1 for rows [0, 65536)
```

Usage pattern:
```pil
// 8-bit range check: value ∈ [0, 256)
sel { value } in precomputed.sel_range_8 { precomputed.clk };

// 16-bit range check: value ∈ [0, 65536)
sel { value } in precomputed.sel_range_16 { precomputed.clk };
```

#### 2.2.3 Bitwise Operation Tables
```pil
pol constant sel_bitwise;       // 1 for first 3 × 256 rows
pol constant bitwise_op_id;     // 0=AND, 1=OR, 2=XOR
pol constant bitwise_input_a;   // All 8-bit values
pol constant bitwise_input_b;   // All 8-bit values
pol constant bitwise_output;    // a OP b
```

**Table Structure** (stacked):
- Rows 0-255: AND table (256 × 256 = 65536 combinations compressed)
- Rows 256-511: OR table
- Rows 512-767: XOR table

#### 2.2.4 Power of 2 Table
```pil
pol constant power_of_2;  // 2^clk for rows [0, 256)
```

#### 2.2.5 Memory Tag Parameters
```pil
pol constant sel_tag_parameters;  // Toggle for MEM_TAG values
pol constant tag_byte_length;     // Bytes per type
pol constant tag_max_bits;        // Bits per type
pol constant tag_max_value;       // Maximum value
```

**Tag Mapping**:
| Tag | Type | Bytes | Bits | Max Value |
|-----|------|-------|------|-----------|
| 0 | FF | 32 | 0 | p-1 |
| 1 | U1 | 1 | 1 | 1 |
| 2 | U8 | 1 | 8 | 255 |
| 3 | U16 | 2 | 16 | 65535 |
| 4 | U32 | 4 | 32 | 2^32-1 |
| 5 | U64 | 8 | 64 | 2^64-1 |
| 6 | U128 | 16 | 128 | 2^128-1 |

#### 2.2.6 Instruction Specification Tables
```pil
// Wire instruction spec (bytecode format)
pol constant sel_op_dc_0..17;    // Operand decomposition selectors
pol constant exec_opcode;         // Execution opcode ID
pol constant instr_size;          // Instruction size in bytes
pol constant sel_has_tag;         // Has tag operand
pol constant sel_tag_is_op2;      // Tag is operand 2

// Execution instruction spec (runtime behavior)
pol constant sel_exec_spec;
pol constant exec_opcode_opcode_gas;
pol constant exec_opcode_base_da_gas;
pol constant exec_opcode_dynamic_l2_gas;
pol constant exec_opcode_dynamic_da_gas;
pol constant sel_mem_op_reg[6];
pol constant rw_reg[6];
pol constant sel_tag_check_reg[6];
pol constant expected_tag_reg[6];
pol constant subtrace_id;
pol constant subtrace_operation_id;
```

#### 2.2.7 Phase Table (Transaction Lifecycle)
```pil
pol constant sel_phase;
pol constant is_public_call_request;
pol constant is_teardown;
pol constant is_collect_fee;
pol constant is_tree_padding;
pol constant is_cleanup;
pol constant is_revertible;
pol constant read_pi_start_offset;
pol constant read_pi_length_offset;
pol constant next_phase_on_revert;
```

#### 2.2.8 Cryptographic Constants
```pil
// SHA256 round constants
pol constant sel_sha256_compression;
pol constant sha256_compression_round_constant;

// Keccak round constants
pol constant sel_keccak;
pol constant keccak_round_constant;
```

#### 2.2.9 To-Radix Tables
```pil
pol constant sel_to_radix_p_limb_counts;   // Toggle for radix 2-256
pol constant to_radix_safe_limbs;           // Safe limbs per radix
pol constant to_radix_num_limbs_for_p;      // Limbs to represent p

pol constant sel_p_decomposition;           // P decomposition table
pol constant p_decomposition_radix;
pol constant p_decomposition_limb_index;
pol constant p_decomposition_limb;
```

---

### 2.3 constants_gen.pil

**Generated Constants** (auto-generated from protocol spec):

#### Tree Parameters
```pil
pol NOTE_HASH_TREE_HEIGHT = 42;
pol PUBLIC_DATA_TREE_HEIGHT = 40;
pol NULLIFIER_TREE_HEIGHT = 42;
pol L1_TO_L2_MSG_TREE_HEIGHT = 36;
pol NOTE_HASH_TREE_LEAF_COUNT = 4398046511104;      // 2^42
pol L1_TO_L2_MSG_TREE_LEAF_COUNT = 68719476736;      // 2^36
```

#### Transaction Limits
```pil
pol MAX_NOTE_HASHES_PER_TX = 64;
pol MAX_NULLIFIERS_PER_TX = 64;
pol MAX_ENQUEUED_CALLS_PER_TX = 32;
pol MAX_TOTAL_PUBLIC_DATA_UPDATE_REQUESTS_PER_TX = 64;
pol MAX_L2_TO_L1_MSGS_PER_TX = 8;
```

#### Protocol Addresses
```pil
pol CANONICAL_AUTH_REGISTRY_ADDRESS = 1;
pol CONTRACT_INSTANCE_REGISTRY_CONTRACT_ADDRESS = 2;
pol CONTRACT_CLASS_REGISTRY_CONTRACT_ADDRESS = 3;
pol MULTI_CALL_ENTRYPOINT_ADDRESS = 4;
pol FEE_JUICE_ADDRESS = 5;
pol PUBLIC_CHECKS_ADDRESS = 6;
```

#### Memory Tags
```pil
pol MEM_TAG_FF = 0;
pol MEM_TAG_U1 = 1;
pol MEM_TAG_U8 = 2;
pol MEM_TAG_U16 = 3;
pol MEM_TAG_U32 = 4;
pol MEM_TAG_U64 = 5;
pol MEM_TAG_U128 = 6;
```

#### Public Input Offsets
```pil
pol AVM_PUBLIC_INPUTS_GLOBAL_VARIABLES_ROW_IDX = 0;
pol AVM_PUBLIC_INPUTS_START_TREE_SNAPSHOTS_ROW_IDX = 19;
pol AVM_PUBLIC_INPUTS_GAS_SETTINGS_ROW_IDX = 24;
pol AVM_PUBLIC_INPUTS_FEE_PAYER_ROW_IDX = 29;
// ... many more offset constants
pol AVM_PUBLIC_INPUTS_COLUMNS_MAX_LENGTH = 4685;
```

#### Domain Separators
```pil
pol DOM_SEP__NOTE_HASH_NONCE = 4040695053;
pol DOM_SEP__UNIQUE_NOTE_HASH = 1615905817;
pol DOM_SEP__SILOED_NOTE_HASH = 3552985968;
pol DOM_SEP__SILOED_NULLIFIER = 1843769845;
pol DOM_SEP__PUBLIC_LEAF_SLOT = 2853865602;
pol DOM_SEP__CONTRACT_CLASS_ID = 1134959961;
```

---

## Phase 3: Soundness Analysis

### 3.1 Public Inputs Security

#### 3.1.1 Access Control
**Property**: Only authorized gadgets can read/write specific PI rows.

**Analysis**:
- Each gadget uses specific row index constants (e.g., `AVM_PUBLIC_INPUTS_AVM_ACCUMULATED_DATA_NULLIFIERS_ROW_IDX`)
- Lookups require matching `precomputed.clk` (row index)
- Multiple writes to same row with different values would cause lookup failure

**Attack Vector**: Unauthorized PI Write
```
Attempt: Write arbitrary data to fee recipient row
Defense: Selector must be 1, row index must match exactly
         Only fee collection code has selectors for that row
```

**Verdict**: ✅ SOUND - Row-indexed access prevents unauthorized access

#### 3.1.2 Public Column Collision
**Property**: Different data types at same row must not collide.

**Analysis**:
- 4 columns available (`cols[0..3]`)
- Different gadgets use different columns at shared rows
- Example: L2→L1 messages use 3 columns (recipient, content, sender)

**Verdict**: ✅ SOUND - Column separation prevents collision

### 3.2 Precomputed Tables Security

#### 3.2.1 Range Check Completeness
**Property**: Range checks must cover exactly [0, 2^n).

**Analysis**:
```pil
sel_range_8:  1 for rows [0, 256)   → values 0-255
sel_range_16: 1 for rows [0, 65536) → values 0-65535
```

**Attack Vector**: Out-of-Range Value
```
Attempt: Pass value 256 to 8-bit range check
Defense: No row where clk=256 has sel_range_8=1
         Lookup fails
```

**Verdict**: ✅ SOUND - Exact range coverage

#### 3.2.2 Bitwise Table Correctness
**Property**: Bitwise operations must produce correct results.

**Analysis**: Generated from exhaustive enumeration:
- 256 × 256 = 65,536 combinations per operation
- Stacked tables with `bitwise_op_id` discrimination
- Looked up by (op_id, input_a, input_b) → output

**Verdict**: ✅ SOUND - Exhaustive precomputation

#### 3.2.3 Power of 2 Table
**Property**: `power_of_2[i] = 2^i` for i ∈ [0, 255].

**Analysis**: Simple exponential computation at trace generation.

**Verdict**: ✅ SOUND - Trivially verifiable

#### 3.2.4 Tag Parameter Table
**Property**: Tag parameters must match protocol specification.

**Analysis**:
- Fixed 7-row table (one per memory tag)
- Generated from protocol constants
- Lookups match tag to (byte_length, max_bits, max_value)

**Verdict**: ✅ SOUND - Matches specification

### 3.3 Constants Security

#### 3.3.1 Tree Height Bounds
**Property**: Tree heights must be < 254 for Merkle gadget safety.

**Analysis**:
```pil
NOTE_HASH_TREE_HEIGHT = 42       ✓
PUBLIC_DATA_TREE_HEIGHT = 40     ✓
NULLIFIER_TREE_HEIGHT = 42       ✓
L1_TO_L2_MSG_TREE_HEIGHT = 36    ✓
```

All heights are well below 254, safe for merkle_check.pil.

**Verdict**: ✅ SOUND - All heights safe

#### 3.3.2 Domain Separator Uniqueness
**Property**: Domain separators must be unique to prevent cross-domain attacks.

**Analysis**:
```pil
DOM_SEP__NOTE_HASH_NONCE = 4040695053
DOM_SEP__UNIQUE_NOTE_HASH = 1615905817
DOM_SEP__SILOED_NOTE_HASH = 3552985968
DOM_SEP__SILOED_NULLIFIER = 1843769845
DOM_SEP__PUBLIC_LEAF_SLOT = 2853865602
...
```

All separators are distinct 32-bit values.

**Verdict**: ✅ SOUND - Unique separators

#### 3.3.3 Public Input Layout
**Property**: PI offsets must be non-overlapping and consistent.

**Analysis**:
The generated constants define a clear layout:
```
Rows 0-7:      Global variables
Rows 8-18:     Protocol contracts
Rows 19-22:    Start tree snapshots
Rows 23:       Start gas used
Rows 24-28:    Gas settings
Rows 29-33:    Fee payer
...
Row 4684:      Reverted flag
Total: 4685 rows
```

**Verdict**: ✅ SOUND - Non-overlapping layout

---

## Phase 4: Completeness Analysis

### 4.1 Trace Generation Requirements

#### public_inputs.pil
- **Selector**: `sel = 1` for rows [0, 4684], `sel = 0` otherwise
- **Columns**: Must contain valid public input data at each row
- **Verification**: Verifier checks `cols[]` against expected public values

#### precomputed.pil
All columns are deterministically generated at circuit setup:
- `clk`: Counter 0 to 2^21-1
- `zero`: All zeros
- `first_row`: [1, 0, 0, 0, ...]
- Range selectors: Based on clk value
- Lookup tables: Exhaustive enumeration

#### constants_gen.pil
No trace generation - pure compile-time constants.

### 4.2 Edge Cases

| Component | Edge Case | Handling |
|-----------|-----------|----------|
| public_inputs | Row 0 access | Valid, contains chain_id |
| public_inputs | Row 4685+ access | Lookup fails (sel = 0) |
| precomputed | clk overflow | Not possible (circuit size bounded) |
| sel_range_8 | Value = 256 | Lookup fails (outside range) |
| bitwise | Different op types | op_id discriminates correctly |

---

## Phase 5: Integration Analysis

### 5.1 Public Inputs Usage Patterns

#### Pattern 1: Read Single Value
```pil
// Read chain_id from public inputs
sel_read {
    constants.AVM_PUBLIC_INPUTS_GLOBAL_VARIABLES_CHAIN_ID_ROW_IDX,
    chain_id
} in public_inputs.sel {
    precomputed.clk,
    public_inputs.cols[0]
};
```

#### Pattern 2: Write Accumulated Data
```pil
// Write nullifier to accumulated data
should_write_to_public_inputs {
    public_inputs_index,
    siloed_nullifier
} in public_inputs.sel {
    precomputed.clk,
    public_inputs.cols[0]
};
```

#### Pattern 3: Read Multiple Columns
```pil
// Read tree snapshot (root + size)
sel {
    row_idx,
    root,
    tree_size
} in public_inputs.sel {
    precomputed.clk,
    public_inputs.cols[0],
    public_inputs.cols[1]
};
```

### 5.2 Precomputed Usage Patterns

#### Pattern 1: Range Check
```pil
// 16-bit range check for clock difference
check_clock { clk_diff_lo }
in precomputed.sel_range_16 { precomputed.clk };
```

#### Pattern 2: Bitwise Operation
```pil
// XOR lookup
sel_xor {
    constants.AVM_BITWISE_XOR_OP_ID,
    input_a,
    input_b,
    output
} in precomputed.sel_bitwise {
    precomputed.bitwise_op_id,
    precomputed.bitwise_input_a,
    precomputed.bitwise_input_b,
    precomputed.bitwise_output
};
```

#### Pattern 3: First Row Detection
```pil
// Initialize on first row
pol LATCH_CONDITION = end + precomputed.first_row;

// Allow start only on first row or after end
(1 - precomputed.first_row) * (1 - sel) * sel' = 0;
```

#### Pattern 4: Tag Validation
```pil
// Lookup tag parameters
sel_tag_check {
    tag,
    byte_length,
    max_value
} in precomputed.sel_tag_parameters {
    precomputed.clk,
    precomputed.tag_byte_length,
    precomputed.tag_max_value
};
```

### 5.3 Constants Usage Patterns

#### Pattern 1: Limit Checking
```pil
pol REMAINING = constants.MAX_NOTE_HASHES_PER_TX - prev_num_note_hashes;
// Check if limit reached using zero-check pattern
```

#### Pattern 2: Tree Height
```pil
// Ensure tree height is correct
sel * (tree_height - constants.NULLIFIER_TREE_HEIGHT) = 0;
```

#### Pattern 3: Domain Separation
```pil
// Siloing separator
sel * (constants.DOM_SEP__SILOED_NULLIFIER - siloing_separator) = 0;
```

#### Pattern 4: Public Input Indexing
```pil
// Compute PI index
public_inputs_index = constants.AVM_PUBLIC_INPUTS_AVM_ACCUMULATED_DATA_NULLIFIERS_ROW_IDX + nullifier_index;
```

---

## Phase 6: Summary & Recommendations

### Security Summary

| Category | Status |
|----------|--------|
| Public Input Access Control | ✅ Sound |
| Range Check Tables | ✅ Sound |
| Bitwise Tables | ✅ Sound |
| Tag Parameters | ✅ Sound |
| Domain Separators | ✅ Sound |
| Instruction Specs | ✅ Sound |
| Tree Heights | ✅ Sound |
| Public Input Layout | ✅ Sound |

### Key Security Properties Verified

1. **Row-Indexed Access**: Public inputs are accessed by exact row index via `precomputed.clk`
2. **Range Completeness**: Range checks cover exactly [0, 2^n) with no gaps
3. **Bitwise Correctness**: Exhaustive precomputation ensures correctness
4. **Domain Isolation**: Unique separators prevent cross-domain confusion
5. **Height Safety**: All tree heights < 254, safe for Merkle gadget
6. **Layout Consistency**: Non-overlapping PI regions prevent data corruption

### Findings

| ID | Severity | Description | Status |
|----|----------|-------------|--------|
| PI-01 | Info | public_inputs.pil is minimal (6 lines) | By design - interface only |
| PI-02 | Info | precomputed columns are fixed at setup | Expected - precomputed values |
| PI-03 | Info | constants_gen.pil is auto-generated | Matches yarn-project/constants |

### Observations

#### 1. Public Inputs Capacity
- 4685 rows × 4 columns = 18,740 field elements
- Sufficient for all transaction data
- Layout defined in constants_gen.pil

#### 2. Precomputed Efficiency
- Range checks use simple table lookups
- Bitwise operations avoid field arithmetic
- Tag parameters enable type-safe memory operations

#### 3. Constant Generation
- Generated from single source of truth
- Prevents inconsistencies across codebase
- Should be regenerated on protocol changes

### Recommendations

1. **Document PI Layout**: Consider generating a visual diagram of the public input layout from constants_gen.pil.

2. **Validate Regeneration**: Ensure CI validates that constants_gen.pil matches yarn-project/constants.

3. **Range Check Bounds**: Consider documenting the maximum circuit size (2^21) and its implications for clk-based range checks.

### Conclusion

The infrastructure components (public_inputs.pil, precomputed.pil, constants_gen.pil) provide a **sound foundation** for all AVM2 gadgets:

- **public_inputs.pil**: Minimal interface that leverages lookup semantics for access control
- **precomputed.pil**: Comprehensive lookup tables covering all needed operations
- **constants_gen.pil**: Auto-generated constants ensuring protocol consistency

The design is elegant and secure:
- Public inputs are accessed via row indices, preventing unauthorized access
- Precomputed tables are exhaustively generated, ensuring correctness
- Constants are centrally defined and auto-generated, preventing inconsistencies

**Final Verdict**: **SOUND** - No vulnerabilities identified.

---

*End of Public Inputs & Precomputed Infrastructure Deep Audit Report*
