# Security Audit: calldata.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `calldata.pil` gadget stores calldata values in a columnar format. Values are hints whose correctness is verified by calldata_hashing.pil via Poseidon2 hash.

### Key Characteristics
- One field per row
- Index increments until latch (end of calldata for a context)
- Empty calldata: special row with index=0, latch=1
- Context IDs must be increasing and non-repeating

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/calldata.pil` | PIL definitions (102 lines) |
| `barretenberg/cpp/pil/vm2/calldata_hashing.pil` | Hash verification |

---

## 3. Constraint Analysis

### 3.1 Trace Shape

**TRACE_CONTINUITY (line 89)**:
```
(1 - precomputed.first_row) * (1 - sel) * sel' = 0
```
- Trace is contiguous

**SEL_TOGGLED_AT_LATCH (line 80)**:
```
latch * (1 - sel) = 0
```
- `latch = 1` implies `sel = 1`

### 3.2 Index Progression

**Index increment (line 84)**:
```
sel * (1 - FIRST_OR_LAST_CALLDATA) * (index' - index - 1) = 0
```
- Index increments by 1 until latch

### 3.3 Context ID Ordering

**CONTEXT_ID_CONTINUITY (line 93)**:
```
(1 - FIRST_OR_LAST_CALLDATA) * (context_id - context_id') = 0
```
- Context ID constant until latch

**RANGE_CHECK_CONTEXT_ID_DIFF (line 100)**:
```
latch { diff_context_id } in precomputed.sel_range_16 { precomputed.clk }
```
Where:
```
diff_context_id = latch * sel' * (context_id' - context_id - 1)
```
- Context IDs strictly increasing (diff >= 1)
- Bounded by 16-bit range check

### 3.4 Value Verification

Values in the calldata column are hints. Correctness is ensured by:
1. **calldata_hashing.pil**: Hashes all values and verifies against public inputs
2. **data_copy.pil**: Looks up values by (index, context_id)

---

## 4. Soundness Analysis

### 4.1 Attack Surface

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Duplicate context IDs | diff_context_id range check | PROTECTED |
| Skip indices | Index increment constraint | PROTECTED |
| Fake values | calldata_hashing verification | PROTECTED |
| Gap in trace | TRACE_CONTINUITY | PROTECTED |

### 4.2 Empty Calldata Handling

Empty calldata uses special row: `index=0, value=0, latch=1`. This is the only case where `index=0` with `sel=1`. Lookups avoid this by starting index at 1.

---

## 5. Findings

### No Critical Vulnerabilities Found

The calldata gadget is **SOUND**.

### INFO-1: Values Are Hints

The comment notes: "The values in the calldata columns are really hints." Their correctness is verified externally by calldata_hashing.pil.

---

## 6. Conclusion

**Status**: SOUND

The calldata.pil gadget correctly implements calldata storage with:
- Proper index sequencing
- Unique, increasing context IDs
- External hash verification for value correctness
