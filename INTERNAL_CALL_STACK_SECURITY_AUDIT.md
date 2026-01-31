# Security Audit: internal_call_stack.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND (N/A - Storage Only)

---

## 1. Overview

The `internal_call_stack.pil` is a pure storage gadget for the internal call stack (INTERNALCALL/INTERNALRETURN opcodes). It tracks return addresses for internal function calls within a single context.

### Key Characteristics
- Storage-only gadget (no logic constraints)
- Partitioned per context (context_id column)
- All active rows defined by permutation from internal_call.pil's `PUSH_CALL_STACK`
- 5 committed columns

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/internal_call_stack.pil` | PIL definitions (29 lines) |

---

## 3. Constraint Analysis

### 3.1 Single Constraint

**Selector boolean (line 12)**:
```
sel * (1 - sel) = 0
```

### 3.2 Columns Stored

- `context_id`: Context to which this stack entry belongs
- `call_id`: ID of the current call frame
- `entered_call_id`: ID of the new call frame (unique key)
- `return_call_id`: ID to restore on return
- `return_pc`: Program counter to restore on return

---

## 4. Soundness Analysis

### 4.1 Security Model

1. **Push (PUSH_CALL_STACK)**: Uses permutation from internal_call.pil
   - Guarantees no fake entries can be added
   - `entered_call_id` acts as unique key per context

2. **Pop (UNWIND_CALL_STACK)**: Uses lookup into `sel`
   - Can only read existing entries
   - Cannot fabricate stack entries

### 4.2 Attack Prevention

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Fake stack entry | Permutation on push | PROTECTED |
| Read non-existent entry | Lookup verifies membership | PROTECTED |
| Cross-context access | context_id in lookup tuple | PROTECTED |

---

## 5. Findings

### Not Applicable (Storage Only)

This gadget has no logic vulnerabilities as it's pure storage.

---

## 6. Conclusion

**Status**: SOUND (N/A - Storage Only)

The internal_call_stack.pil is a minimal storage gadget for internal call returns. Security is determined by its usage in internal_call.pil.
