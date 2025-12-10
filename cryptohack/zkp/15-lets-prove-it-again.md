# Let's Prove It Again (175 pts)

## Challenge Overview

This challenge presents a Schnorr identification protocol with Fiat-Shamir transformation. The server implements a proof system where we can request multiple proofs and optionally refresh the random seed.

## Vulnerability Analysis

The critical vulnerability lies in the reuse of the commitment randomness `v` across all proofs within a connection. Additionally, we can control the PRNG seed after getting 2 proofs, allowing us to predict the prime `p` used in subsequent proofs.

### Key Observations

1. **Single `v` for all proofs**: The value `v = R.getrandbits(512)` is set once in `__init__` and reused for all 4 proofs

2. **Controllable seed**: After 2 proofs, we can refresh with our own seed, making the PRNG deterministic

3. **Predictable `p`**: After refreshing, the prime `p` generated for the next proof is predictable since we control the PRNG seed

4. **Same `p` for two proofs**: By refreshing twice with the SAME seed, we get two proofs that share the same prime `p`

## The Attack

### Protocol Flow

```
1. get_proof (enables refresh)     → turn 1, unpredictable p
2. refresh with known seed X       → R = Random(nonce + X)
3. get_proof                       → turn 2, predictable p (proof A)
4. get_proof (enables refresh)     → turn 3, unpredictable p
5. refresh with SAME seed X        → R = Random(nonce + X)
6. get_proof                       → turn 4, same p as proof A! (proof B)
```

### Mathematical Exploitation

For proofs A and B with the same `p`:
- `rA = (v - cA * FLAG) mod (p-1)`
- `rB = (v - cB * FLAG) mod (p-1)`

Subtracting:
```
rA - rB = (cB - cA) * FLAG mod (p-1)
```

Therefore:
```
FLAG = (rA - rB) * inverse(cB - cA, p-1) mod (p-1)
```

### Challenge Computation

The challenges `cA` and `cB` are SHA3-256 hashes that include a random component from 2 to 1024. We brute-force this small range (~1023 values each) to find the correct challenges, verified by:
```python
check = (pow(g, r, p) * pow(y, c, p)) % p
assert check == t
```

## Solution

```python
#!/usr/bin/env python3
from pwn import *
import json
import random
import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime

BITS = 2 << 9  # 1024
g = 2

def getPrime_deterministic(R, N):
    while True:
        number = R.getrandbits(N) | 1
        if isPrime(number, randfunc=lambda x: long_to_bytes(R.getrandbits(x))):
            return number

conn = remote('socket.cryptohack.org', 13431)
nonce = bytes.fromhex(conn.recvline_contains(b'nonce').decode().split(': ')[1])

known_seed = b'\x00' * 8

# Get two proofs with same p
conn.sendline(json.dumps({"option": "get_proof"}).encode())
conn.recvline()

conn.sendline(json.dumps({"option": "refresh", "seed": known_seed.hex()}).encode())
conn.recvline()

conn.sendline(json.dumps({"option": "get_proof"}).encode())
proofA = json.loads(conn.recvline().decode())

conn.sendline(json.dumps({"option": "get_proof"}).encode())
conn.recvline()

conn.sendline(json.dumps({"option": "refresh", "seed": known_seed.hex()}).encode())
conn.recvline()

conn.sendline(json.dumps({"option": "get_proof"}).encode())
proofB = json.loads(conn.recvline().decode())
conn.close()

# Predict p
R = random.Random(nonce + known_seed)
p = getPrime_deterministic(R, BITS)

# Find challenges by brute-force
tA, rA, yA = proofA['t'], proofA['r'], proofA['y']
tB, rB, yB = proofB['t'], proofB['r'], proofB['y']

for rand in range(2, BITS + 1):
    c = bytes_to_long(hashlib.sha3_256(long_to_bytes(tA ^ yA ^ g ^ rand)).digest())
    if (pow(g, rA, p) * pow(yA, c, p)) % p == tA:
        cA = c
        break

for rand in range(2, BITS + 1):
    c = bytes_to_long(hashlib.sha3_256(long_to_bytes(tB ^ yB ^ g ^ rand)).digest())
    if (pow(g, rB, p) * pow(yB, c, p)) % p == tB:
        cB = c
        break

# Solve for FLAG
FLAG_num = ((rA - rB) * pow(cB - cA, -1, p - 1)) % (p - 1)
FLAG_bytes = long_to_bytes(FLAG_num)

# Reverse XOR with nonce and remove inserted byte
# ... (decoding logic for the flag transformation)
```

## Flag

*(captured)*

## Root Cause

The vulnerability is a classic nonce reuse attack on Schnorr-like protocols. The commitment randomness `v` should be unique for each proof, but here it's reused across all proofs in a session. Combined with the ability to control the PRNG seed and get proofs with the same prime, this allows algebraic recovery of the secret (FLAG).

## Remediation

1. Generate fresh `v` for each proof
2. Don't allow user-controlled seeds
3. Use a proper key derivation function instead of `Random(nonce + seed)`
