# Diffusion through Permutation (30 pts)

**Category:** AES — How AES Works
**Difficulty:** Easy

---

## Challenge

Understand how ShiftRows and MixColumns provide diffusion in AES.

---

## Vulnerability

Diffusion spreads plaintext influence across the ciphertext. Without it, changing one plaintext byte would only affect one ciphertext byte.

**Key insight:** After just 2 rounds, every output byte depends on every input byte—this is AES's full diffusion property.

---

## Solution

```python
def shift_rows(state):
    """Cyclically shift rows left by 0, 1, 2, 3 positions"""
    return [
        state[0],                          # Row 0: no shift
        state[1][1:] + state[1][:1],       # Row 1: shift left 1
        state[2][2:] + state[2][:2],       # Row 2: shift left 2
        state[3][3:] + state[3][:3],       # Row 3: shift left 3
    ]

def mix_columns(state):
    """Mix each column using matrix multiplication in GF(2^8)"""
    # Multiply each column by fixed matrix:
    # | 2 3 1 1 |
    # | 1 2 3 1 |
    # | 1 1 2 3 |
    # | 3 1 1 2 |
    pass  # Implementation uses GF(2^8) arithmetic
```

---

## Key Takeaway

**Diffusion spreads influence rapidly.** In AES:
- ShiftRows moves bytes between columns
- MixColumns mixes bytes within columns
- Together: 1 byte change → 4 bytes after 1 round → 16 bytes after 2 rounds
- This rapid diffusion is called the "wide trail" strategy

