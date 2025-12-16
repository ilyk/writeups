# Additive (70 pts)

**Category:** Diffie-Hellman — Group Theory
**Difficulty:** Medium

---

## Challenge

The server implements "Diffie-Hellman" using an additive group instead of multiplicative.

---

## Vulnerability

**Multiplicative DH (secure):**
```
A = g^a mod p     (exponentiation)
s = B^a mod p     (hard to reverse)
```

**Additive DH (broken):**
```
A = a * g mod p   (multiplication)
s = a * B mod p   (trivially reversible!)
```

In additive notation, recovering `a` from `A = a * g` is just division:
```
a = A * g^(-1) mod p
```

---

## Solution

```python
from pwn import remote
import hashlib
import json

conn = remote('socket.cryptohack.org', 13380)

# Get parameters
data = json.loads(conn.recvline())
p, g, A = data['p'], data['g'], data['A']

# In additive group: A = a * g mod p
# Recover a: a = A * g^(-1) mod p
a = (A * pow(g, -1, p)) % p

# Get Bob's public value
data = json.loads(conn.recvline())
B = data['B']

# Compute shared secret: s = a * B mod p
shared_secret = (a * B) % p

# Decrypt flag
key = hashlib.sha1(str(shared_secret).encode()).digest()[:16]
# ... decrypt with AES
```

---

## Mathematical Comparison

| Operation | Multiplicative | Additive |
|-----------|----------------|----------|
| Public key | A = g^a | A = a·g |
| Inverse problem | DLP (hard) | Division (easy) |
| Security | ✓ Secure | ✗ Broken |

---

## Key Takeaway

**DH security depends on the discrete log problem being hard.** In additive groups over Z/pZ, "discrete log" is just modular division—trivial to compute. This is why DH uses multiplicative groups (or elliptic curves where addition IS the hard operation).
