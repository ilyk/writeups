# Flipping Cookie (60 pts)

**Category:** AES — Block Ciphers 1
**Difficulty:** Medium

---

## Challenge

A CBC-encrypted cookie contains `admin=False`. Flip bits to make it `admin=True`.

---

## Vulnerability

CBC decryption XORs each ciphertext block with the decrypted next block. Flipping bits in ciphertext flips corresponding bits in the plaintext of the next block.

**Key insight:** `C[i] ⊕ X` causes `P[i+1]` to become `P[i+1] ⊕ X` after decryption. We can calculate exactly which bits to flip.

---

## Solution

```python
def flip_cookie(ciphertext, iv):
    """Flip bits to change 'admin=False' to 'admin=True;'"""
    ct = bytearray(ciphertext)

    # Find which block contains 'False' (check block alignment)
    # Flip bits in the PREVIOUS block to affect target

    # Calculate XOR mask
    original = b"False"
    target = b"True;"  # Same length!

    mask = bytes(a ^ b for a, b in zip(original, target))

    # Apply mask to previous block at correct offset
    offset = ...  # Position of 'False' in its block
    prev_block_start = ...  # Start of previous block

    for i, m in enumerate(mask):
        ct[prev_block_start + offset + i] ^= m

    return bytes(ct)
```

---

## Key Takeaway

**CBC bit-flipping enables targeted plaintext modification.** Constraints:
- Flipping in block N corrupts block N's plaintext (random garbage)
- But precisely controls block N+1's plaintext
- Same-length substitutions avoid padding issues

Mitigation: Always use authenticated encryption (GCM, ChaCha20-Poly1305) to detect tampering.

