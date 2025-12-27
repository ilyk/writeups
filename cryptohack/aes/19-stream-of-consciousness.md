# Stream of Consciousness (80 pts)

**Category:** AES — Stream Ciphers
**Difficulty:** Medium

---

## Challenge

Exploit keystream reuse in a CTR-mode implementation.

---

## Vulnerability

When the same keystream is used to encrypt multiple messages, XORing ciphertexts reveals the XOR of plaintexts.

**Key insight:** `C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2`. With known plaintext for one message, the other is revealed.

---

## Solution

```python
def two_time_pad_attack(c1, c2, known_p1):
    """Recover P2 when keystream is reused"""
    # C1 = P1 ⊕ keystream
    # C2 = P2 ⊕ keystream
    # C1 ⊕ C2 = P1 ⊕ P2

    # If we know P1:
    # P2 = C1 ⊕ C2 ⊕ P1 = C2 ⊕ keystream

    xored = bytes(a ^ b for a, b in zip(c1, c2))
    p2 = bytes(a ^ b for a, b in zip(xored, known_p1))
    return p2

# For multiple ciphertexts with same keystream:
# Use crib dragging - guess common words and check if results make sense
```

---

## Key Takeaway

**Keystream reuse is the "two-time pad" attack.** This breaks:
- CTR with reused nonce
- OFB with reused IV
- Any stream cipher with key/IV reuse

Historical examples: WEP (IV space too small), PPTP (same key for both directions), various CTF challenges.

