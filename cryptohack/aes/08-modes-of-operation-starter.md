# Modes of Operation Starter (15 pts)

**Category:** AES — Symmetric Starter
**Difficulty:** Easy

---

## Challenge

Decrypt an AES-CBC encrypted message using a provided key and IV.

---

## Vulnerability

CBC mode XORs each plaintext block with the previous ciphertext block before encryption. The IV is the "previous ciphertext" for the first block.

**Key insight:** Knowing the key and IV allows complete decryption—there's no secret beyond the key itself.

---

## Solution

```python
from Crypto.Cipher import AES

key = bytes.fromhex("...")  # provided key
iv = bytes.fromhex("...")   # provided IV
ciphertext = bytes.fromhex("...")

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
print(plaintext.decode())
```

---

## Key Takeaway

**Modes of operation extend block ciphers to arbitrary-length messages.** CBC properties:
- Requires random, unpredictable IV for each encryption
- IV doesn't need to be secret, just unique
- Error propagation: 1 bit error affects 2 blocks
- Padding oracle attacks possible if decryption errors leak

