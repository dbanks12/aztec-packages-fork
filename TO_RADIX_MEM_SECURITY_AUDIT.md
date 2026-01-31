# Security Audit: to_radix_mem.pil

**Audit Date**: 2024
**Auditor**: Claude Code Security Audit
**Status**: SOUND (Virtual to to_radix.pil)

---

## 1. Overview

The `to_radix_mem.pil` is a virtual gadget to `to_radix.pil` that handles the TORADIXBE opcode. It reads a field element, decomposes it using the to_radix core, and writes the limbs to memory in big-endian order.

### Key Characteristics
- Virtual to to_radix.pil (shares namespace)
- Big-endian output (reverses little-endian from core)
- Error handling: invalid radix, invalid num_limbs, out-of-bounds, truncation
- Multi-row with limb index decrementing for reversal

---

## 2. Files Analyzed

| File | Purpose |
|------|---------|
| `barretenberg/cpp/pil/vm2/to_radix_mem.pil` | PIL constraint definitions (virtual to to_radix.pil) |

Note: This audit reviews the memory integration portion. The core decomposition logic was audited in TO_RADIX_SECURITY_AUDIT.md.

---

## 3. Constraint Analysis

### 3.1 Error Detection

**Invalid Radix**:
- Radix must be 2-256 (handled by to_radix core)
- TORADIXBE only supports radix = 2

**Invalid Num Limbs**:
- Checked against maximum allowed for the radix

**Out of Bounds**:
- Destination address + num_limbs checked against AVM_HIGHEST_MEM_ADDRESS

**Truncation Error**:
- If value doesn't fit in the specified number of limbs

### 3.2 Big-Endian Reversal

The core to_radix produces little-endian limbs. For big-endian output:
- Memory writes start at `dst_addr + num_limbs - 1`
- Address decrements each row
- First limb (LSB) written last in memory

### 3.3 Ghost Row Protection

**sel_should_write_mem constraint**:
```
sel_should_write_mem * (1 - sel) = 0
```
- Prevents inactive rows from firing memory write permutations

### 3.4 Memory Writes

- Each limb written with tag U8 (for radix <= 256)
- Uses slice write pattern similar to other memory gadgets

---

## 4. Soundness Analysis

### 4.1 Attack Surface Analysis

| Attack Vector | Protection | Status |
|---------------|------------|--------|
| Invalid radix | Error detection at start | PROTECTED |
| Invalid num_limbs | Error detection | PROTECTED |
| Dst out of bounds | gt gadget lookup | PROTECTED |
| Truncation | Truncation error flag | PROTECTED |
| Ghost memory writes | sel_should_write_mem guard | PROTECTED |
| Reorder limbs | Decrementing index constraint | PROTECTED |

### 4.2 Integration with to_radix Core

The to_radix core ensures:
- Limb values are < radix
- Accumulator correctly reconstructs value
- Overflow protection against field modulus

The memory wrapper adds:
- Address bounds checking
- Error consolidation
- Big-endian reversal

---

## 5. Findings

### No Critical Vulnerabilities Found

The to_radix_mem gadget is **SOUND**.

### INFO-1: TORADIXBE vs TORADIXLE

TORADIXBE (big-endian) requires the reversal logic. A hypothetical TORADIXLE would write directly in the order produced by the core.

### INFO-2: Radix Limitation

While to_radix supports radix 2-256, TORADIXBE may have additional restrictions based on the opcode specification.

---

## 6. Conclusion

**Status**: SOUND

The to_radix_mem gadget correctly implements big-endian radix decomposition with:
- Proper reversal of little-endian core output
- Comprehensive error handling
- Ghost row protection for memory writes

The constraint system is complete and no soundness vulnerabilities were identified.
