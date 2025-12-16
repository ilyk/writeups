# Parameter Injection (60 pts)

**Category:** Diffie-Hellman — Man In The Middle
**Difficulty:** Medium

---

## Challenge

Exploit a man-in-the-middle position to force a known shared secret in DH key exchange.

---

## Vulnerability

In unauthenticated DH, a MITM can replace public values with malicious ones. The classic attack: replace both public values with `p` itself.

**Why `p` works:**
```
A' = p ≡ 0 (mod p)
B' = p ≡ 0 (mod p)

Alice computes: s = B'^a = 0^a = 0 (mod p)
Bob computes:   s = A'^b = 0^b = 0 (mod p)
```

Both compute shared secret = 0!

---

## Solution

```python
from pwn import remote
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import json

conn = remote('socket.cryptohack.org', 13371)

# Intercept Alice's parameters
data = json.loads(conn.recvline())
p, g, A = data['p'], data['g'], data['A']

# Send p to Bob (forces shared secret = 0)
conn.sendline(json.dumps({'p': p, 'g': g, 'A': p}).encode())

# Intercept Bob's response
data = json.loads(conn.recvline())
B = data['B']

# Send p to Alice
conn.sendline(json.dumps({'B': p}).encode())

# Shared secret is 0
shared_secret = 0

# Get encrypted flag
data = json.loads(conn.recvline())
iv = bytes.fromhex(data['iv'])
ciphertext = bytes.fromhex(data['encrypted_flag'])

# Decrypt
key = hashlib.sha1(str(shared_secret).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ciphertext), 16)
```

---

## Key Takeaway

**Unauthenticated DH is vulnerable to MITM attacks.** Solutions:
1. **Authenticated DH** (signed public values)
2. **Station-to-Station protocol**
3. **TLS with certificates**

The attacker doesn't need to solve any hard problems—just substitute parameters.
