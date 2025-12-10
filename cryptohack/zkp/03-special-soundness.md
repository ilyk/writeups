# Special Soundness — Witness Extraction via Randomness Reuse (25 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Easy

> *The prover spoke the same riddle twice, with two different keys. From the delta between answers, the secret emerged—arithmetic laid bare. Special soundness: the property that proves security, weaponized to extract secrets when randomness fails.*

---

## Executive Summary

This challenge demonstrates the "special soundness" property of Sigma protocols: given two accepting transcripts with the same commitment but different challenges, an extractor can compute the witness. While this property is essential for proving security (it shows that accepting provers must "know" the witness), it becomes a devastating attack when provers reuse randomness across protocol runs.

**Flag:** *(captured)*

---

## Challenge Description

The server implements a Schnorr proof of knowledge protocol but makes a critical mistake: it reuses the same randomness `r` for multiple protocol executions. By requesting two transcripts with different challenges, we can extract the secret witness using simple algebra.

**Vulnerable Code:**
```python
# Server (VULNERABLE)
class Prover:
    def __init__(self, flag):
        self.flag = flag
        self.r = random.randint(0, q)  # Generated ONCE

    def prove(self, challenge):
        a = pow(g, self.r, p)  # Same 'a' every time!
        z = (self.r + challenge * self.flag) % q
        return (a, z)
```

---

## Vulnerability Analysis

### The Special Soundness Property

**Definition:** A Sigma protocol has special soundness if there exists an efficient extractor E such that:
- Given two accepting transcripts (a, e₁, z₁) and (a, e₂, z₂)
- With the same commitment **a** but different challenges **e₁ ≠ e₂**
- E can compute the witness **w**

**Why This Is Good:** Special soundness proves that a cheating prover (without the witness) cannot answer two different challenges for the same commitment except with negligible probability. This is evidence that the prover must "know" the witness.

**Why This Is Bad:** When randomness is reused, an attacker acting as a malicious verifier can intentionally request multiple challenges and extract the witness!

---

### Mathematical Extraction

Given two transcripts:
```
Transcript 1: (a, e₁, z₁) where z₁ = r + e₁·w  (mod q)
Transcript 2: (a, e₂, z₂) where z₂ = r + e₂·w  (mod q)
```

**Extraction Steps:**
```
z₁ - z₂ = (r + e₁·w) - (r + e₂·w)  (mod q)
z₁ - z₂ = e₁·w - e₂·w  (mod q)
z₁ - z₂ = (e₁ - e₂)·w  (mod q)

w = (z₁ - z₂) · (e₁ - e₂)⁻¹  (mod q)
```

**Verification:**
```
g^w ≟ y  (mod p)  ✓
```

---

## Exploitation

### Step 1: Request First Transcript

```python
#!/usr/bin/env python3
from pwn import remote
from Crypto.Util.number import inverse

conn = remote('socket.cryptohack.org', 13427)

# Receive public parameters
conn.recvuntil(b'p = ')
p = int(conn.recvline())
conn.recvuntil(b'q = ')
q = int(conn.recvline())
conn.recvuntil(b'g = ')
g = int(conn.recvline())

# Round 1: Get first transcript
conn.recvuntil(b'a = ')
a1 = int(conn.recvline().strip(), 16)

conn.recvuntil(b'y = ')
y = int(conn.recvline().strip(), 16)

# Send first challenge
e1 = 12345
conn.sendline(str(e1).encode())

conn.recvuntil(b'z = ')
z1 = int(conn.recvline().strip(), 16)

print(f"Transcript 1: (a={hex(a1)[:20]}..., e={e1}, z={hex(z1)[:20]}...)")
```

### Step 2: Request Second Transcript

```python
# Server says: "not convinced? I'll happily do it again!"

# Round 2: Get second transcript
conn.recvuntil(b'a = ')
a2 = int(conn.recvline().strip(), 16)

assert a1 == a2, "ERROR: Commitments differ! Randomness was fresh."
print(f"✓ Same commitment detected! Randomness reused: a1 == a2")

# Send different challenge
e2 = 67890
conn.sendline(str(e2).encode())

conn.recvuntil(b'z = ')
z2 = int(conn.recvline().strip(), 16)

print(f"Transcript 2: (a={hex(a2)[:20]}..., e={e2}, z={hex(z2)[:20]}...)")
```

### Step 3: Extract the Witness

```python
# Extract flag using special soundness
numerator = (z1 - z2) % q
denominator = (e1 - e2) % q
flag_int = (numerator * inverse(denominator, q)) % q

# Verify extraction
assert pow(g, flag_int, p) == y, "Extraction failed!"
print(f"✓ Witness extracted and verified!")

# Convert to bytes and extract flag string
from Crypto.Util.number import long_to_bytes
flag_bytes = long_to_bytes(flag_int)
flag = flag_bytes.decode('ascii', errors='ignore')

print(f"\nFlag: {flag}")
# Flag received!
```

### Complete Exploit

```python
#!/usr/bin/env python3
from pwn import remote
from Crypto.Util.number import inverse, long_to_bytes

conn = remote('socket.cryptohack.org', 13427)

# Parse parameters
conn.recvuntil(b'p = ')
p = int(conn.recvline())
conn.recvuntil(b'q = ')
q = int(conn.recvline())
conn.recvuntil(b'g = ')
g = int(conn.recvline())

# Collect two transcripts with different challenges
transcripts = []
challenges = [12345, 67890]

for e in challenges:
    conn.recvuntil(b'a = ')
    a = int(conn.recvline().strip(), 16)
    if not transcripts:
        conn.recvuntil(b'y = ')
        y = int(conn.recvline().strip(), 16)

    conn.sendline(str(e).encode())

    conn.recvuntil(b'z = ')
    z = int(conn.recvline().strip(), 16)

    transcripts.append((a, e, z))

# Verify same commitment (randomness reused)
assert transcripts[0][0] == transcripts[1][0], "Commitments differ!"

# Extract witness
a1, e1, z1 = transcripts[0]
a2, e2, z2 = transcripts[1]

flag_int = ((z1 - z2) * inverse(e1 - e2, q)) % q

# Verify
assert pow(g, flag_int, p) == y

# Decode flag
flag = long_to_bytes(flag_int).decode('ascii', errors='ignore')
print(flag)

conn.close()
```

---

## Root Causes

1. **Randomness Reuse**: The nonce `r` is generated once and reused across protocol runs
2. **No State Management**: The protocol doesn't track or prevent repeated use of the same commitment
3. **Interactive Verifier**: An honest verifier wouldn't request multiple proofs, but a malicious one can
4. **Missing Freshness Check**: No mechanism to ensure each proof uses fresh randomness

---

## Real-World Impact

### Historical Exploits

**1. Sony PlayStation 3 ECDSA Hack (2010)**
- PS3 firmware signatures used ECDSA with reused nonces
- fail0verflow team extracted Sony's private key
- Complete compromise of PS3 security model
- **Same mathematical attack**: (s₁ - s₂)/(h₁ - h₂) = k, then extract private key

**2. Bitcoin Wallet Thefts**
- Buggy wallet implementations reused ECDSA nonces
- Attackers monitored blockchain for repeated `r` values
- Extracted private keys, stole funds
- Multiple incidents, millions of dollars lost

**3. Android SecureRandom Bug**
- Android Bitcoin wallets used weak RNG
- Predictable nonces led to key extraction
- August 2013: millions in Bitcoin stolen

---

## Remediation

### Immediate Fixes

**1. Fresh Randomness Per Execution**
```python
class SecureProver:
    def prove(self, challenge):
        r = secrets.randbelow(q)  # Fresh r EVERY TIME
        a = pow(g, r, p)
        z = (r + challenge * self.flag) % q
        return (a, z)
```

**2. Deterministic Nonces (RFC 6979)**
```python
def generate_deterministic_nonce(private_key, message, q):
    """
    RFC 6979: Deterministic nonce generation
    k = HMAC_DRBG(private_key || message)
    """
    import hmac, hashlib

    h = hmac.new(private_key, message, hashlib.sha256)
    k = int.from_bytes(h.digest(), 'big') % q
    return k
```

**3. Non-Interactive (Fiat-Shamir)**
```python
def fiat_shamir_proof(g, y, w, p, q):
    """
    Non-interactive proof using Fiat-Shamir
    Verifier cannot request multiple proofs!
    """
    r = secrets.randbelow(q)
    a = pow(g, r, p)

    # Challenge derived from commitment (deterministic)
    e = int.from_bytes(sha256(str(a).encode()).digest(), 'big') % q

    z = (r + e * w) % q

    return (a, z)  # No interaction needed
```

### Defense in Depth

**4. Commitment Tracking**
```python
class StatefulProver:
    def __init__(self, flag):
        self.flag = flag
        self.used_commitments = set()

    def prove(self, challenge):
        r = secrets.randbelow(q)
        a = pow(g, r, p)

        # Prevent reuse
        if a in self.used_commitments:
            raise Exception("Commitment reuse detected!")
        self.used_commitments.add(a)

        z = (r + challenge * self.flag) % q
        return (a, z)
```

---

## Key Takeaways

1. **Special Soundness is a Double-Edged Sword**: It proves security (prover must know witness) but enables extraction (if you can get two transcripts)

2. **Randomness Reuse = Game Over**: In crypto protocols, reusing nonces is catastrophic—whether in ZK proofs, signatures, or encryption

3. **Fresh ≠ Random**: Even "random" values must be fresh (unique per execution); deterministic generation (RFC 6979) is safer than buggy RNG

4. **Non-Interactive Eliminates the Attack**: Fiat-Shamir transformation prevents verifier from requesting multiple transcripts

5. **Real-World Consequences**: This isn't academic—nonce reuse has cost millions in Bitcoin thefts and compromised major systems

---

## Mathematical Deep Dive

### Why Extraction Works

The Schnorr protocol's response equation is:
```
z = r + e·w  (mod q)
```

This is a **linear equation** in the unknown `w`. With one equation and two unknowns (`r` and `w`), we can't solve for `w`.

But with **two equations** (same `r`, different `e`):
```
z₁ = r + e₁·w  (mod q)
z₂ = r + e₂·w  (mod q)
```

Now we have a system of two equations with two unknowns. Subtracting eliminates `r`:
```
z₁ - z₂ = (e₁ - e₂)·w  (mod q)
```

And we can solve for `w`:
```
w = (z₁ - z₂) · (e₁ - e₂)⁻¹  (mod q)
```

**The Attack Only Works When:**
- Same `r` is used (gives same `a`)
- Different `e` values (otherwise equations are identical)
- `e₁ ≠ e₂` (otherwise denominator is zero)

---

## Protocol Comparison

| Property | Vulnerable | Secure |
|----------|-----------|--------|
| **Randomness** | Reused across runs | Fresh per execution |
| **State Tracking** | None | Tracks used commitments |
| **Interactivity** | Interactive | Non-interactive (Fiat-Shamir) |
| **Witness Security** | ❌ Extractable | ✅ Protected |
| **Real-World Use** | ⚠️ PS3, broken wallets | ✅ Modern systems |

---

## References

- [Damgård, I.: "On Σ-Protocols"](https://www.cs.au.dk/~ivan/Sigma.pdf)
- [RFC 6979: Deterministic ECDSA/DSA](https://datatracker.ietf.org/doc/html/rfc6979)
- [fail0verflow: PS3 ECDSA Vulnerability](https://www.youtube.com/watch?v=LP1t_pzxKyE)
- [Bitcoin Nonce Reuse Incidents](https://www.nilsschneider.net/2013/01/28/recovering-bitcoin-private-keys.html)

---

> *The same riddle, asked twice. The same answer, keyed differently. The delta spoke volumes—and from it, the secret. Special soundness: a proof of security turned weapon. The lesson echoes through cryptographic history: randomness must be fresh, or all is lost.*
