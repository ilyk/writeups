# Passwords as Keys (50 pts)

**Category:** AES — Symmetric Starter
**Difficulty:** Easy

---

## Challenge

A weak password was hashed with MD5 and used as an AES key. Recover the plaintext.

---

## Vulnerability

Using password-derived keys without proper key derivation functions (KDFs) enables dictionary attacks.

**Key insight:** MD5 is fast—attackers can hash millions of password guesses per second. Proper KDFs (PBKDF2, Argon2) add deliberate slowness.

---

## Solution

```python
from Crypto.Cipher import AES
import hashlib

# Common password wordlist
with open("/usr/share/dict/words") as f:
    words = [w.strip().lower() for w in f]

ciphertext = bytes.fromhex("...")

for password in words:
    key = hashlib.md5(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        plaintext = cipher.decrypt(ciphertext)
        if b"crypto{" in plaintext:
            print(f"Password: {password}")
            print(f"Flag: {plaintext}")
            break
    except:
        continue
```

---

## Key Takeaway

**Never use raw password hashes as keys.** Problems:
- Fast hashes enable brute-force (billions of MD5/sec on GPU)
- Low entropy passwords have maybe 30-40 bits of security
- No salt means precomputed rainbow tables work

Use proper KDFs: PBKDF2 (minimum), bcrypt, scrypt, or Argon2 (best).

