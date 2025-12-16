# Static Client (100 pts)

**Category:** Diffie-Hellman — Group Theory
**Difficulty:** Medium

---

## Challenge

A client reuses the same static DH key pair for multiple sessions. Exploit this to recover their secret.

---

## Vulnerability

**Ephemeral DH (secure):** Fresh key pair each session
**Static DH (vulnerable):** Same key pair reused

When the client has static keys (a, A = g^a), we can:
1. Send a malicious public value A' = A (their own public key)
2. They compute shared secret s = A'^b = A^b
3. We receive their public value B = g^b
4. We compute s = B^a... but we don't know a

**The trick:** Set our generator g' = A. Then:
- Client computes: s = (g')^b = A^b
- We know B = g^b and A = g^a
- We compute: s = B^a = (g^b)^a = g^(ab) = A^b ✓

Wait, we still need `a`. The actual attack is subtler:

**Attack:** Send g' = 1. Then A' = g'^a = 1^a = 1 for any a.
- Client computes: s = 1^b = 1
- Shared secret is always 1!

---

## Solution

```python
from pwn import remote
import hashlib
import json

conn = remote('socket.cryptohack.org', 13373)

# Get client's static public key
data = json.loads(conn.recvline())
p, g, A = data['p'], data['g'], data['A']

# Send malicious parameters: g' = 1
# Then any A' becomes 1^a = 1, and shared secret = 1^b = 1
conn.sendline(json.dumps({
    'p': p,
    'g': 1,
    'A': 1
}).encode())

# Shared secret is 1
shared_secret = 1

# Get encrypted flag
data = json.loads(conn.recvline())
iv = bytes.fromhex(data['iv'])
ciphertext = bytes.fromhex(data['encrypted'])

# Decrypt
key = hashlib.sha1(str(shared_secret).encode()).digest()[:16]
# ... decrypt with AES
```

---

## Key Takeaway

**Static DH keys are dangerous without proper validation.** Defenses:
1. Always use ephemeral keys (ECDHE)
2. Validate received parameters (g ≠ 1, A ≠ 1, etc.)
3. Use authenticated key exchange

Modern TLS prefers ephemeral DH precisely to avoid static key vulnerabilities.
