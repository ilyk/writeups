# Export-grade (100 pts)

**Category:** Diffie-Hellman — Man In The Middle
**Difficulty:** Medium

---

## Challenge

Exploit weak "export-grade" DH parameters to recover the shared secret.

---

## Background

In the 1990s, US export regulations mandated weak cryptography for exported software. "Export-grade" DH used small primes (~512 bits) that are now easily broken.

The **Logjam attack** (2015) showed that many servers still accept these weak parameters.

---

## Vulnerability

When the server accepts small primes:
1. MITM requests weak DH parameters
2. Small prime → discrete log is feasible
3. Attacker solves DLP and recovers shared secret

---

## Solution

```python
from pwn import remote
from sympy.ntheory import discrete_log
import hashlib
import json

conn = remote('socket.cryptohack.org', 13379)

# Request weak parameters
conn.sendline(json.dumps({
    'supported': ['DH64', 'DH128', 'DH256']  # Request small primes
}).encode())

# Get parameters with small prime
data = json.loads(conn.recvline())
p, g, A = data['p'], data['g'], data['A']

# For small p, solve discrete log: find a such that g^a = A (mod p)
a = discrete_log(p, A, g)

# Send our public value
b = 2  # Our private key (arbitrary)
B = pow(g, b, p)
conn.sendline(json.dumps({'B': B}).encode())

# Compute shared secret
data = json.loads(conn.recvline())
shared_secret = pow(data['B'], a, p)  # Or pow(A, b, p)

# Decrypt flag
iv = bytes.fromhex(data['iv'])
ciphertext = bytes.fromhex(data['encrypted_flag'])
key = hashlib.sha1(str(shared_secret).encode()).digest()[:16]
# ... decrypt with AES
```

---

## Key Takeaway

**Never accept weak DH parameters.** Modern recommendations:
- Minimum 2048-bit primes
- Prefer ephemeral ECDH (faster, smaller keys)
- Reject downgrade attacks at protocol level

The Logjam attack showed even 512-bit DH can be broken in minutes with precomputation.
