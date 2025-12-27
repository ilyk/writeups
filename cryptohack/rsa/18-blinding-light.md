# Blinding Light (120 pts)

**Category:** RSA — Signatures Part 1
**Difficulty:** Medium

---

## Challenge

A token signing and verification server with "safeguards" to prevent signing admin tokens. The server uses textbook RSA signatures.

---

## Vulnerability

The server blocks signing `admin=True` directly but uses textbook RSA without hashing. RSA's multiplicative property allows signature forgery via blinding:

**Key insight:** For RSA signature s = m^d mod N, we can compute:
- Blinded message: m' = m × r^e mod N
- Blinded signature: s' = (m')^d = m^d × r mod N
- Unblind: s = s' × r^(-1) mod N = m^d mod N

---

## Solution

```python
from pwn import *
import json
import random

def query(opt_dict):
    conn = remote('socket.cryptohack.org', 13376)
    conn.recvline()
    conn.sendline(json.dumps(opt_dict).encode())
    return json.loads(conn.recvline().decode())

# Get public key
pubkey = query({'option': 'get_pubkey'})
N = int(pubkey['N'], 16)
e = int(pubkey['e'], 16)

# Target message (blocked from direct signing)
target = b'admin=True'
M = int.from_bytes(target, 'big')

# RSA Blinding Attack
r = random.randint(2, N-1)
M_blind = (M * pow(r, e, N)) % N

# Get signature on blinded message
blind_hex = hex(M_blind)[2:]
if len(blind_hex) % 2: blind_hex = '0' + blind_hex
result = query({'option': 'sign', 'msg': blind_hex})
s_blind = int(result['signature'], 16)

# Unblind to get forged signature
s = (s_blind * pow(r, -1, N)) % N

# Verify with forged signature
v = query({'option': 'verify', 'msg': target.hex(), 'signature': hex(s)})
print(v)  # Contains flag
```

---

## Key Takeaway

**Textbook RSA signatures are malleable.** The multiplicative property s(a×b) = s(a)×s(b) enables blinding attacks. Protection requires:
- Hash-then-sign (hash message before signing)
- PKCS#1 v1.5 or PSS padding schemes
- Never use raw RSA for signatures

RSA blinding is also used legitimately for privacy-preserving signatures, but here it bypasses access controls.

