# Mixed Up (120 pts)

**Category:** Hash Functions — Pre-image
**Difficulty:** Hard

---

## Challenge

A custom mixing function shuffles data based on bitwise operations:
- `mixed_and = data AND FLAG`
- `mixed_xor = data XOR FLAG`
- `very_mixed[i] = mixed_xor[mixed_and[i] % L]`

Returns `SHA256(very_mixed)`.

---

## Vulnerability

The mixing function has an **algebraic weakness**. When `data = [0]*L`:
- `mixed_and = [0]*L` (all indices become 0)
- `mixed_xor = FLAG`
- `very_mixed = [FLAG[0]]*L` (all positions get the same byte)

This means `SHA256([b]*L)` has only **256 possible values** regardless of FLAG length!

---

## Solution

```python
from hashlib import sha256

def precompute_hashes(L):
    """Compute all 256 possible hashes when very_mixed = [b]*L"""
    return {sha256(bytes([b] * L)).hexdigest() for b in range(256)}

def find_flag_length(conn):
    """Find FLAG length by testing when hash matches precomputed set"""
    for L in range(8, 60):
        H = precompute_hashes(L)
        data = bytes([0] * L)
        h = get_hash(conn, data.hex())
        if h in H:
            return L
    return None

def extract_flag(conn, L):
    """Extract FLAG bit by bit"""
    H = precompute_hashes(L)
    flag = bytearray(L)

    for k in range(L):
        char_val = 0
        for b in range(8):
            mask = 1 << b
            data = bytearray([0] * L)
            data[k] = mask

            # If bit b of FLAG[k] is 0: mixed_and[k] = 0, index stays 0
            # If bit b of FLAG[k] is 1: mixed_and[k] = mask, index changes
            h = get_hash(conn, bytes(data).hex())
            if h not in H:
                char_val |= mask  # Bit is set in FLAG

        flag[k] = char_val

    return bytes(flag)
```

**Attack:**
1. Find FLAG length by testing when `data = [0]*L` produces hash in precomputed set
2. For each bit position, test if setting that bit changes the index (reveals FLAG bit)
3. Reconstruct FLAG character by character

---

## Key Takeaway

**Custom hash constructions often have algebraic shortcuts.** The mixing function intended to obscure data, but choosing `data = [0]` collapses the mixing to a trivial case. Always analyze edge cases and degeneracies in custom crypto.
