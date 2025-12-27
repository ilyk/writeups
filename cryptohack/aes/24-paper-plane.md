# Paper Plane (120 pts)

**Category:** AES — Authenticated Encryption
**Difficulty:** Hard

---

## Challenge

Exploit a vulnerability in Telegram's MTProto IGE mode implementation.

---

## Vulnerability

IGE (Infinite Garble Extension) mode XORs both plaintext and ciphertext with neighboring blocks, but doesn't provide authentication.

**Key insight:** Without MAC verification, IGE is vulnerable to padding oracle attacks when error messages differ based on padding validity.

---

## Solution

```python
def ige_padding_oracle_attack(ciphertext, iv, oracle):
    """
    IGE mode: C[i] = E(P[i] ⊕ C[i-1]) ⊕ P[i-1]
    Decryption: P[i] = D(C[i] ⊕ P[i-1]) ⊕ C[i-1]

    Padding oracle still works because:
    - Modifying C[i-1] XORs with D(C[i])
    - Same byte-at-a-time attack as CBC
    """
    block_size = 16

    # Split IV (IGE uses double-width IV)
    iv1, iv2 = iv[:16], iv[16:]

    # Attack proceeds similarly to CBC padding oracle
    # but accounting for IGE's different XOR structure
    # ...
```

---

## Key Takeaway

**Encryption without authentication is incomplete.** IGE problems:
- Padding validity leaks information
- No integrity check allows tampering
- Error handling reveals decryption state

MTProto v2.0 added HMAC verification. Modern systems should use AEAD (AES-GCM, ChaCha20-Poly1305).

