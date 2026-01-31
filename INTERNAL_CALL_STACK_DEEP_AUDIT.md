# Deep Security Audit: internal_call_stack.pil & internal_call.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Type**: DEEP AUDIT (Full Methodology)
**Status**: SOUND

---

## Audit Checklist

### Phase 1: Discovery
- [x] Located PIL files: `pil/vm2/internal_call_stack.pil` (29 lines), `pil/vm2/opcodes/internal_call.pil` (95 lines)
- [x] Located context.pil (call ID columns)
- [x] Located callers: execution.pil (INTERNAL_CALL, INTERNAL_RETURN)

### Phase 2: Understanding
- [x] Documented gadget purpose (internal call stack management)
- [x] Listed all witnesses
- [x] Listed all constraints
- [x] Understood push/pop mechanism

### Phase 3: Soundness
- [x] Verified permutation for push
- [x] Analyzed lookup for pop
- [x] Checked error handling (empty stack)
- [x] Verified call ID management

### Phase 4: Completeness
- [x] Reviewed ID propagation
- [x] Checked edge cases
- [x] Verified error gating

### Phase 5: Integration
- [x] Verified execution dispatch
- [x] Checked context interaction

---

## 1. Files Analyzed

| File | Lines | Purpose |
|------|-------|---------|
| `pil/vm2/internal_call_stack.pil` | 29 | Stack storage |
| `pil/vm2/opcodes/internal_call.pil` | 95 | Push/pop operations |

---

## 2. Gadget Architecture

### 2.1 Purpose

The internal call stack manages INTERNAL_CALL and INTERNAL_RETURN opcodes within a single context. Unlike external calls (which create new contexts), internal calls stay within the same memory space but need to track return PCs.

### 2.2 Stack Entry Structure

```
+------------+------------+------------------+----------------+-----------+
| context_id | call_id    | entered_call_id  | return_call_id | return_pc |
+------------+------------+------------------+----------------+-----------+
```

- `context_id`: Identifies which context the entry belongs to
- `call_id`: Current internal call ID when push happened
- `entered_call_id`: New call ID being entered (next_internal_call_id)
- `return_call_id`: Call ID to restore on return
- `return_pc`: PC to return to

### 2.3 Call ID Management

Three columns in context.pil track internal calls:
- `internal_call_id`: Current call ID
- `internal_call_return_id`: Parent call ID (for return)
- `next_internal_call_id`: Next available call ID

---

## 3. Push Operation (INTERNAL_CALL)

### 3.1 Permutation Constraint

```pil
// internal_call.pil:74-79
#[PUSH_CALL_STACK]
sel_execute_internal_call {
    context_id, next_internal_call_id, internal_call_id, internal_call_return_id, next_pc
} is internal_call_stack.sel {
    internal_call_stack.context_id, internal_call_stack.entered_call_id,
    internal_call_stack.call_id, internal_call_stack.return_call_id, internal_call_stack.return_pc
};
```

**Uses `is` (permutation)**: Critical for security - prevents malicious prover from inserting fake stack entries.

### 3.2 ID Updates on Call

```pil
// internal_call.pil:58-66
#[NEW_CALL_ID_ON_CALL]
sel_execute_internal_call * (internal_call_id' - next_internal_call_id) = 0;

#[NEW_RETURN_ID_ON_CALL]
sel_execute_internal_call * (internal_call_return_id' - internal_call_id) = 0;

#[INCR_NEXT_INT_CALL_ID]
SEL_INTERNAL_OP * (next_internal_call_id' - (next_internal_call_id + sel_execute_internal_call)) = 0;
```

**Analysis**:
- `internal_call_id' = next_internal_call_id` (enter new call)
- `internal_call_return_id' = internal_call_id` (save current as parent)
- `next_internal_call_id' = next_internal_call_id + 1` (increment for next call)

---

## 4. Pop Operation (INTERNAL_RETURN)

### 4.1 Error Detection

```pil
// internal_call.pil:39-46
pol commit sel_read_unwind_call_stack;
sel_read_unwind_call_stack = sel_execute_internal_return * (1 - sel_opcode_error);

#[INTERNAL_RET_ERROR]
sel_execute_internal_return * (internal_call_return_id * (sel_opcode_error * (1 - internal_call_return_id_inv)
    + internal_call_return_id_inv) - 1 + sel_opcode_error) = 0;
```

**Analysis**: Zero-check pattern ensures `sel_opcode_error = 1` iff `internal_call_return_id = 0` (empty stack).

### 4.2 Lookup Constraint

```pil
// internal_call.pil:89-94
#[UNWIND_CALL_STACK]
sel_read_unwind_call_stack {
    context_id, internal_call_id, internal_call_id', internal_call_return_id', pc'
} in internal_call_stack.sel {
    internal_call_stack.context_id, internal_call_stack.entered_call_id,
    internal_call_stack.call_id, internal_call_stack.return_call_id, internal_call_stack.return_pc
};
```

**Uses `in` (lookup)**: Safe for read-only operation. Gated by `sel_read_unwind_call_stack` which is 0 when error occurs.

### 4.3 Lookup Key

The lookup uses `(context_id, internal_call_id)` as the key, matching against `(context_id, entered_call_id)` in the stack. This correctly identifies which call to return from.

---

## 5. Internal Call Stack Storage

```pil
// internal_call_stack.pil
namespace internal_call_stack;
    pol commit sel; // @boolean
    sel * (1 - sel) = 0;

    #[skippable_if]
    sel = 0;

    pol commit context_id;
    pol commit call_id;
    pol commit entered_call_id;
    pol commit return_call_id;
    pol commit return_pc;
```

**Analysis**: The storage trace has no constraints beyond `sel` boolean. All semantics come from:
- Permutation `#[PUSH_CALL_STACK]` ensures legitimate entries
- Lookup `#[UNWIND_CALL_STACK]` reads from these entries

---

## 6. Soundness Verification

### 6.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Forge stack entry | #[PUSH_CALL_STACK] permutation | PROTECTED |
| Return from wrong call | Lookup keyed by (context_id, internal_call_id) | PROTECTED |
| Return from empty stack | #[INTERNAL_RET_ERROR] zero-check | PROTECTED |
| Skip error check | sel_read_unwind_call_stack gating | PROTECTED |
| Wrong PC on return | Lookup enforces return_pc | PROTECTED |
| Cross-context attack | context_id in lookup key | PROTECTED |

### 6.2 Critical Security Properties

#### 6.2.1 Permutation vs Lookup Choice

From comments:
> Crucial to be a permutation to prevent malicious insertions in the internal call stack.

> Fine to be a lookup since we are not modifying the stack (cannot be a permutation because an error might occur before the read).

The choice is correct:
- **Push (permutation)**: 1:1 correspondence between INTERNAL_CALL and stack entry
- **Pop (lookup)**: Read-only, error-gated, allows same entry to be read if somehow needed

#### 6.2.2 Context Isolation

Stack entries include `context_id`, preventing cross-context stack manipulation.

#### 6.2.3 Call ID Uniqueness

Each internal call gets a unique ID via `next_internal_call_id` increment. The pair `(context_id, entered_call_id)` uniquely identifies each stack entry.

---

## 7. Findings

### No Critical Vulnerabilities Found

The internal_call_stack gadget is **SOUND**.

### INFO-1: Minimal Storage Trace

The internal_call_stack.pil has almost no constraints - just 5 columns and sel boolean. All semantics are enforced by the permutation/lookup from internal_call.pil.

### INFO-2: Infallible INTERNAL_CALL

From execution.pil:
```pil
#[INFALLIBLE_OPCODES_SUCCESS]
(... + sel_execute_internal_call + ...) * sel_opcode_error = 0;
```

INTERNAL_CALL cannot error. Only INTERNAL_RETURN can error (empty stack).

### INFO-3: Asymmetric Push/Pop

- Push is always executed (no error case)
- Pop is gated by error check

This asymmetry is correct: pushing is always valid, but popping from empty stack must error.

---

## 8. Conclusion

**Status**: SOUND

The internal call stack system is **correctly implemented** with:

- Permutation for push preventing malicious insertions
- Error-gated lookup for pop
- Correct empty stack detection via zero-check
- Proper call ID management (current, return, next)
- Context isolation via context_id in keys
- Unique entry identification via (context_id, entered_call_id)

No soundness or completeness vulnerabilities were identified in this deep audit.

---

## Appendix: Constraint Summary

| Constraint | File | Purpose |
|------------|------|---------|
| PUSH_CALL_STACK | internal_call.pil | Permutation for push |
| UNWIND_CALL_STACK | internal_call.pil | Lookup for pop |
| INTERNAL_RET_ERROR | internal_call.pil | Empty stack error |
| NEW_CALL_ID_ON_CALL | internal_call.pil | Update call ID |
| NEW_RETURN_ID_ON_CALL | internal_call.pil | Update return ID |
| INCR_NEXT_INT_CALL_ID | internal_call.pil | Increment next ID |

## Appendix: Call ID Lifecycle

```
INTERNAL_CALL:
  internal_call_id' = next_internal_call_id  (enter new call)
  internal_call_return_id' = internal_call_id  (save parent)
  next_internal_call_id' = next_internal_call_id + 1

INTERNAL_RETURN (no error):
  internal_call_id' = call_id from stack  (restore)
  internal_call_return_id' = return_call_id from stack  (restore parent)
  pc' = return_pc from stack  (jump back)
  next_internal_call_id' = next_internal_call_id  (unchanged)

INTERNAL_RETURN (error - empty stack):
  sel_opcode_error = 1
  (no stack lookup, values unconstrained)
```
