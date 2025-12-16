# Deriving Symmetric Keys (40 pts)

**Category:** Diffie-Hellman — Starter
**Difficulty:** Easy

---

## Challenge

Derive an AES key from a DH shared secret and decrypt the flag.

---

## Solution

DH shared secrets are large integers unsuitable for direct use as symmetric keys. A **Key Derivation Function (KDF)** converts them to fixed-length keys:

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Compute shared secret
shared_secret = pow(B, a, p)

# Derive AES key using SHA-1 (as specified in challenge)
key = hashlib.sha1(str(shared_secret).encode()).digest()[:16]

# Decrypt
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(ciphertext), 16)
```

---

## Key Takeaway

**Never use raw DH output as a key.** Always apply a proper KDF (HKDF, SHA-256, etc.) to:
1. Fix the key length
2. Extract entropy uniformly
3. Provide domain separation

Modern protocols use HKDF (RFC 5869) rather than simple hashing.
