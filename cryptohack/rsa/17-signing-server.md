# Signing Server (60 pts)

**Category:** RSA — Signatures Part 1
**Difficulty:** Easy

---

## Challenge

A signing server that "signs everything automatically" and also stores encrypted messages. The boss has many emails to process.

---

## Vulnerability

The server has no restrictions on what messages it will sign. When asked to sign the encrypted secret, it simply returns the decrypted plaintext as the "signature."

**Key insight:** The "signature" output contains the actual message, not a cryptographic signature. The server confused signing with decryption or simply returned the plaintext.

---

## Solution

```python
from pwn import *
import json

conn = remote('socket.cryptohack.org', 13374)
conn.recvline()  # Welcome

# Get the secret (encrypted flag)
conn.sendline(json.dumps({'option': 'get_secret'}).encode())
secret = json.loads(conn.recvline().decode())

# Ask server to "sign" the secret
conn.sendline(json.dumps({'option': 'sign', 'msg': secret['secret']}).encode())
result = json.loads(conn.recvline().decode())

# The "signature" is actually the decrypted message!
sig_bytes = bytes.fromhex(result['signature'][2:])
print(sig_bytes.decode())  # Contains the flag
```

---

## Key Takeaway

**Signing oracles must validate input.** A signing server should:
- Never sign arbitrary data without authentication
- Never return plaintext in signature responses
- Distinguish between signing and decryption operations
- Implement message format restrictions

This challenge demonstrates what happens when a "signing" endpoint is actually a decryption oracle in disguise.

