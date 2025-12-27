# XOR Starter (10 pts)

**Category:** General — XOR
**Difficulty:** Easy

---

## Challenge

XOR the string "label" with the integer 13.

---

## Vulnerability

XOR (exclusive or) is the fundamental operation in symmetric cryptography. It has perfect properties:
- `A ⊕ A = 0` (self-inverse)
- `A ⊕ 0 = A` (identity)
- `A ⊕ B = B ⊕ A` (commutative)
- `(A ⊕ B) ⊕ C = A ⊕ (B ⊕ C)` (associative)

**Key insight:** XOR each byte of the message with the key byte.

---

## Solution

```python
message = "label"
key = 13

# XOR each character with the key
result = ''.join(chr(ord(c) ^ key) for c in message)
print(result)
```

---

## Key Takeaway

**XOR is reversible with the same key.** If `C = P ⊕ K`, then `P = C ⊕ K`. This property makes XOR the basis of:
- Stream ciphers (XOR plaintext with keystream)
- Block cipher modes (CBC, CTR, etc.)
- One-time pad (theoretically unbreakable if key is random and used once)
