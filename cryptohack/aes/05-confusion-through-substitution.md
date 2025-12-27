# Confusion through Substitution (25 pts)

**Category:** AES — How AES Works
**Difficulty:** Easy

---

## Challenge

Understand the AES S-box and how it provides confusion.

---

## Vulnerability

The S-box provides non-linearity—without it, AES would be a linear function easily broken with linear algebra.

**Key insight:** The S-box is computed as multiplicative inverse in GF(2^8) followed by an affine transformation, providing high non-linearity.

---

## Solution

```python
def sub_bytes(state):
    """Apply S-box to each byte of state"""
    return [[s_box[b] for b in row] for row in state]

def inv_sub_bytes(state):
    """Apply inverse S-box for decryption"""
    return [[inv_s_box[b] for b in row] for row in state]

# S-box provides:
# - Non-linearity (breaks linear relationships)
# - Confusion (obscures relationship between key and ciphertext)
# - No fixed points except 0x00 (in standard AES S-box)
```

---

## Key Takeaway

**S-boxes provide confusion (Shannon).** Properties of AES S-box:
- Maximum non-linearity possible for 8-bit bijection
- Designed to resist differential and linear cryptanalysis
- Algebraic structure (GF(2^8) inverse) enables efficient implementation
- The "linear" property refers to approximations that enable linear cryptanalysis

