# PIL Gadget Security Audit Methodology

## Overview

This document outlines the systematic approach for auditing PIL (Polynomial Identity Language) gadgets in the AVM2 codebase.

---

## Audit Steps

### Phase 1: Discovery and Context Gathering

1. **Identify all related files**:
   - PIL constraint file (`pil/vm2/<gadget>.pil`)
   - Simulation gadget (`simulation/gadgets/<gadget>.cpp`, `.hpp`)
   - Trace generation (`tracegen/<gadget>_trace.cpp`, `.hpp`)
   - Event definitions (`simulation/events/<gadget>_event.hpp`)
   - Generated relations (`generated/relations/<gadget>.hpp`, `_impl.hpp`)
   - Generated lookups (`generated/relations/lookups_<gadget>.hpp`)
   - Tests (`simulation/gadgets/<gadget>.test.cpp`, `constraining/relations/<gadget>.test.cpp`)
   - Fuzzers (`avm_fuzzer/harness/<gadget>.fuzzer.cpp`)

2. **Identify callers/users of the gadget**:
   - Search for lookups INTO this gadget from other PIL files
   - Search for simulation calls to this gadget from other gadgets
   - Understand the trust boundaries and assumptions

### Phase 2: Understand the Gadget

3. **Read the PIL file thoroughly**:
   - Document the purpose of the gadget
   - List all committed polynomials (witnesses)
   - List all constraints (polynomial identities)
   - List all lookups (both into precomputed tables and between gadgets)
   - Identify selector patterns and mutual exclusivity

4. **Trace through the data flow**:
   - How does data enter the gadget? (via lookups from other gadgets)
   - What computations are performed?
   - What properties are being proven?
   - How is the result used by callers?

### Phase 3: Soundness Analysis

5. **Verify each constraint**:
   - Does the constraint correctly enforce the intended property?
   - Are there ways to satisfy the constraint with invalid values?
   - Check for field arithmetic issues (overflow, underflow, wraparound)

6. **Analyze attack vectors**:
   - Can a malicious prover provide invalid witness values that satisfy constraints?
   - Can lookups be bypassed or manipulated?
   - Are selector flags properly constrained (boolean, mutually exclusive)?
   - Are there edge cases where constraints don't apply?

7. **Check lookup soundness**:
   - Are lookup selectors correctly gated?
   - Do lookups check all necessary tuple elements?
   - Could a prover satisfy lookups with unintended values?

### Phase 4: Completeness Analysis

8. **Review trace generation**:
   - Does trace generation produce valid witnesses for all valid inputs?
   - Are there edge cases where valid inputs produce invalid traces?
   - Check for uninitialized variables, integer overflow, off-by-one errors
   - Verify all columns are properly set for each row

9. **Verify simulation correctness**:
   - Does simulation correctly compute expected results?
   - Are events emitted with correct values?
   - Are preconditions checked appropriately?

10. **Check test coverage**:
    - Are edge cases tested (min/max values, boundary conditions)?
    - Are negative tests included (invalid inputs should fail)?
    - Does fuzzing cover the full input space?

### Phase 5: Integration Analysis

11. **Verify usage by callers**:
    - Do callers use the gadget correctly?
    - Are preconditions satisfied by all call sites?
    - Could incorrect usage lead to soundness issues?

12. **Check cross-gadget interactions**:
    - Are shared columns used consistently?
    - Do lookups between gadgets have matching schemas?
    - Are there circular dependencies that could cause issues?

### Phase 6: Documentation

13. **Document findings**:
    - CRITICAL: Soundness bugs (malicious prover can create invalid proofs)
    - CRITICAL: Completeness bugs (honest prover cannot create valid proofs)
    - HIGH: Issues that could lead to soundness/completeness under certain conditions
    - MEDIUM: Defense-in-depth issues, potential for future bugs
    - LOW: Code quality issues, undefined behavior, missing tests
    - INFO: Observations, design decisions, areas for improvement

14. **Provide recommendations**:
    - Specific code changes to fix issues
    - Additional tests to add
    - Documentation improvements

---

## Checklist Template

```markdown
## [Gadget Name] Audit Checklist

### Phase 1: Discovery
- [ ] Located PIL file
- [ ] Located simulation code
- [ ] Located trace generation
- [ ] Located tests
- [ ] Identified all callers

### Phase 2: Understanding
- [ ] Documented gadget purpose
- [ ] Listed all witnesses
- [ ] Listed all constraints
- [ ] Listed all lookups
- [ ] Understood data flow

### Phase 3: Soundness
- [ ] Verified each constraint
- [ ] Analyzed attack vectors
- [ ] Checked lookup soundness
- [ ] Verified selector constraints

### Phase 4: Completeness
- [ ] Reviewed trace generation
- [ ] Checked for uninitialized variables
- [ ] Verified edge case handling
- [ ] Reviewed test coverage

### Phase 5: Integration
- [ ] Verified caller usage
- [ ] Checked cross-gadget interactions

### Phase 6: Documentation
- [ ] Documented all findings
- [ ] Provided recommendations
```

---

## Common Vulnerability Patterns

### Soundness Issues
1. **Missing constraint gating**: Constraint doesn't check selector, applies to all rows
2. **Incomplete lookups**: Lookup doesn't include all necessary columns
3. **Integer overflow in field**: Computation wraps around field modulus unexpectedly
4. **Selector not boolean**: Selector can be values other than 0/1
5. **Non-unique decomposition**: Value can be represented multiple ways

### Completeness Issues
1. **Uninitialized witness columns**: Trace generation doesn't set all required values
2. **Integer overflow in trace gen**: C++ computation overflows before field conversion
3. **Off-by-one errors**: Loop bounds incorrect, boundary conditions wrong
4. **Missing edge cases**: Special values (0, max, boundaries) not handled

### Integration Issues
1. **Schema mismatch**: Lookup tuple elements don't match between source and destination
2. **Precondition violation**: Caller doesn't satisfy gadget's expected input constraints
3. **Selector collision**: Same selector used for incompatible purposes
