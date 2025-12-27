# Symmetry (50 pts)

**Category:** AES — Stream Ciphers
**Difficulty:** Medium

---

## Challenge

Exploit OFB mode's symmetry property to decrypt without knowing the key.

---

## Vulnerability

OFB mode generates a keystream by encrypting the IV repeatedly. The keystream is identical for encryption and decryption.

**Key insight:** In OFB, `E(P) = P ⊕ keystream` and `D(C) = C ⊕ keystream`. If we have an encryption oracle, we can decrypt by encrypting!

---

## Solution

```python
def ofb_attack(encrypt_oracle, ciphertext, iv):
    """OFB encryption = decryption with same IV"""
    # OFB keystream is: E(IV), E(E(IV)), E(E(E(IV))), ...
    # Encryption: C = P ⊕ keystream
    # Decryption: P = C ⊕ keystream

    # If we have an encryption oracle with same key/IV:
    # encrypt(C) = C ⊕ keystream = P

    plaintext = encrypt_oracle(ciphertext, iv)
    return plaintext
```

---

## Key Takeaway

**OFB mode is symmetric—encryption equals decryption.** This means:
- An encryption oracle IS a decryption oracle
- IV reuse is catastrophic: same keystream, easy XOR recovery
- OFB converts block cipher to stream cipher

Modern alternative: CTR mode (parallelizable, same symmetry property but with counter for unique keystream blocks).

