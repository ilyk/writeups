# Invariant (250 pts)

**Category:** Hash Functions — Pre-image
**Difficulty:** Very Hard

---

## Challenge

Custom hash using Davies-Meyer construction with a custom cipher. Find a preimage that hashes to all zeros.

---

## Vulnerability

The cipher has an **invariant subspace**. The S-box has a 2-cycle: `SBOX[6] = 7` and `SBOX[7] = 6`.

**Key insight:** The subspace where all nibbles are in `{6, 7}` is invariant under:
- S-box (maps {6,7} to {6,7})
- Subkey XOR (0 or 1 doesn't leave {6,7})
- XOR mixing ({6,7} XOR {0,1} = {6,7})
- ShiftRows (just permutation)

For Davies-Meyer: `h' = E_k(m) XOR m`
- If `m` and `E_k(m)` are both in {6,7}^16
- Then `h' = m XOR E_k(m)` is in {0,1}^16

---

## Solution

```python
from hashlib import sha512

SBOX = [13, 14, 0, 1, 5, 10, 7, 6, 11, 3, 9, 12, 15, 8, 2, 4]

def nibbles_to_bytes(nibbles):
    """Convert 16 nibbles to 8 bytes"""
    result = []
    for i in range(0, 16, 2):
        result.append((nibbles[i] << 4) | nibbles[i+1])
    return bytes(result)

def search_invariant_subspace():
    """Search all 2^16 messages in {6,7}^16"""
    for i in range(2**16):
        # Convert i to 16 nibbles, each in {6, 7}
        nibbles = [(6 if ((i >> j) & 1) == 0 else 7) for j in range(16)]
        m = nibbles_to_bytes(nibbles)

        h = my_hash(m)

        if h == b"\x00" * 8:
            return m

    return None
```

**Attack:**
1. Identify the invariant subspace {6,7}^16
2. Search all 2^16 = 65536 messages in this subspace
3. Find message where `E_k(m) = m` (fixed point in Davies-Meyer)
4. This produces `h = m XOR m = 0`

---

## Key Takeaway

**Invariant subspace attacks exploit algebraic structure in ciphers.** When S-boxes have cycles or fixed points, they can create subspaces that remain closed under encryption. The reduced search space (2^16 vs 2^64) makes preimage search feasible.
