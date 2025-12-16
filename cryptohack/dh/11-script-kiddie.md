# Script Kiddie (70 pts)

**Category:** Diffie-Hellman — Miscellaneous
**Difficulty:** Medium

---

## Challenge

A programmer implemented Diffie-Hellman but made a critical coding mistake.

---

## Vulnerability

The implementation uses Python's XOR operator (`^`) instead of modular exponentiation:

```python
# INTENDED (secure DH):
b = pow(g, secret, p)
shared = pow(A, secret, p)

# ACTUAL (broken):
b = g ^ secret       # XOR, not exponentiation!
shared = A ^ b       # XOR, not exponentiation!
```

In Python:
- `^` = bitwise XOR
- `**` = exponentiation
- `pow(b, e, m)` = modular exponentiation

---

## Attack

Since the server computes:
```
B = g ^ secret
shared = A ^ b    where b = B ^ g
```

We can recover the shared secret:
```python
b = B ^ g           # XOR is self-inverse
shared = A ^ b      # Same computation as server
```

---

## Solution

```python
from pwn import remote
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import json

conn = remote('socket.cryptohack.org', 13432)

# Get parameters
alice_data = json.loads(conn.recvline())
p, g, A = alice_data['p'], alice_data['g'], alice_data['A']

bob_data = json.loads(conn.recvline())
B = bob_data['B']

enc_data = json.loads(conn.recvline())
iv = bytes.fromhex(enc_data['iv'])
ciphertext = bytes.fromhex(enc_data['encrypted_flag'])

# Exploit: XOR instead of pow
b = B ^ g
shared_secret = A ^ b
# Equivalently: shared_secret = A ^ B ^ g

# Decrypt
key = hashlib.sha1(str(shared_secret).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ciphertext), 16)
```

---

## Key Takeaway

**Operator confusion can be catastrophic.** In Python:

| Operator | Meaning |
|----------|---------|
| `^` | Bitwise XOR |
| `**` | Exponentiation |
| `pow(b,e,m)` | Modular exponentiation |

Always review cryptographic code for such mistakes. XOR-based "DH" provides zero security—the shared secret is directly computable from public values.
