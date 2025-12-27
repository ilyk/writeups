# Lazy CBC (60 pts)

**Category:** AES — Block Ciphers 1
**Difficulty:** Medium

---

## Challenge

An implementation reuses the key as the IV. Exploit this to recover the key.

---

## Vulnerability

When IV = Key, an attacker with a decryption oracle can recover the key by exploiting CBC's XOR structure.

**Key insight:** For CBC decryption, `P[0] = D(C[0]) ⊕ IV`. If we can make `D(C[0])` known, we recover `IV = Key`.

---

## Solution

```python
def attack(encrypt, decrypt):
    """Recover key when IV = Key"""
    # Encrypt any known plaintext
    plaintext = b"A" * 48  # 3 blocks
    ciphertext = encrypt(plaintext)

    # Craft malicious ciphertext: C[0] || 0...0 || C[0]
    # This makes decryption reveal the key
    block = ciphertext[:16]
    zeros = b"\x00" * 16
    crafted = block + zeros + block

    # Decrypt crafted ciphertext
    decrypted = decrypt(crafted)

    # P'[0] = D(C[0]) ⊕ IV = D(C[0]) ⊕ Key
    # P'[2] = D(C[0]) ⊕ C[1] = D(C[0]) ⊕ 0 = D(C[0])
    # Therefore: Key = P'[0] ⊕ P'[2]

    key = bytes(a ^ b for a, b in zip(decrypted[:16], decrypted[32:48]))
    return key
```

---

## Key Takeaway

**IV must be independent of the key.** Using `IV = Key` leaks the key because:
- CBC structure allows algebraic manipulation
- Decryption oracle reveals internal state
- XOR relationships expose the key directly

IVs should be random and unique per encryption, never derived from the key.

