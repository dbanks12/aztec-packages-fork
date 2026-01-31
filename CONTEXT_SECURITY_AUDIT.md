# Security Audit: context.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND

---

## 1. Overview

The `context.pil` is a virtual gadget within the execution trace that manages context changes during external calls, returns, and reverts. It handles context ID tracking, gas management, tree state, and stack operations.

### Key Characteristics
- Virtual gadget (part of execution trace)
- Manages 40+ context columns
- Interacts with context_stack.pil for push/pop operations
- Handles nested and enqueued calls

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/context.pil` | PIL constraint definitions (914 lines) |
| `barretenberg/cpp/pil/vm2/context_stack.pil` | Stack storage (62 lines) |

---

## 3. Constraint Analysis

### 3.1 Row Partitioning

Every active row falls into exactly one category:
1. `sel_enter_call = 1`: Entering nested call
2. `nested_return = 1`: Returning from nested call
3. `nested_failure = 1`: Reverting/erroring from nested call
4. `enqueued_call_end = 1`: Exiting top-level enqueued call
5. `DEFAULT_CTX_ROW = 1`: All other rows

```
DEFAULT_CTX_ROW = sel - sel_enter_call - sel_exit_call
```

### 3.2 Context ID Management

**CONTEXT_ID_EXT_CALL (line 217)**:
```
sel_enter_call * (context_id' - next_context_id) = 0
```

**CONTEXT_ID_NESTED_EXIT (line 219)**:
```
NESTED_EXIT_CALL * (context_id' - parent_id) = 0
```

**INCR_NEXT_CONTEXT_ID (line 207)**:
```
NOT_LAST_EXEC * (next_context_id' - (next_context_id + sel_first_row_in_context')) = 0
```

### 3.3 Context Stack Operations

**CTX_STACK_CALL (lines 636-698)**: Permutation
- Pushes context state when entering a nested call
- Uses `next_context_id` as unique key

**CTX_STACK_ROLLBACK (lines 704-767)**: Lookup
- Restores full context (including trees) on nested failure

**CTX_STACK_RETURN (lines 774-812)**: Lookup
- Restores partial context (not trees) on nested return

### 3.4 Tree State Continuity

**NOT_LAST_NOT_FAILURE_NOT_ENQ_END (line 877)**:
```
NOT_LAST_NOT_FAILURE_NOT_ENQ_END * (note_hash_tree_root - prev_note_hash_tree_root') = 0
```
- Tree state propagates forward except on failure (rollback) or enqueued call end

### 3.5 Gas Management

**L2_GAS_USED_INGEST_AFTER_EXIT (line 843)**:
```
NESTED_EXIT_CALL * (parent_l2_gas_used + l2_gas_used - prev_l2_gas_used') = 0
```
- Parent inherits child's gas usage on exit

---

## 4. Soundness Analysis

### 4.1 Attack Surface

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Fake context push | Permutation (not lookup) | PROTECTED |
| Wrong context restore | Unique key (entered_context_id) | PROTECTED |
| Tree state manipulation | Rollback via lookup | PROTECTED |
| Gas manipulation | Proper propagation constraints | PROTECTED |
| Skip context operations | Selector partition | PROTECTED |

### 4.2 Permutation vs Lookup

- **CTX_STACK_CALL**: Uses permutation (`is`) - critical for security
- **CTX_STACK_ROLLBACK/RETURN**: Uses lookup (`in`) - safe since they only read

---

## 5. Findings

### No Critical Vulnerabilities Found

The context gadget is **SOUND**.

### INFO-1: Large Context State

The context manages 40+ columns, making it one of the most complex gadgets. All propagation paths are properly constrained for each partition case.

### INFO-2: Tree Rollback on Failure

On nested failure, tree state is rolled back via CTX_STACK_ROLLBACK. On nested return, tree state is NOT rolled back (child's changes are adopted).

---

## 6. Conclusion

**Status**: SOUND

The context.pil gadget correctly implements context management with:
- Proper context ID sequencing
- Secure stack operations via permutation/lookup
- Correct tree state handling for success/failure paths
- Gas accounting across nested calls
