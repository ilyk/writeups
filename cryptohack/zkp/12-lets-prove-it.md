# Let's Prove It — Malicious Verifier Extraction (150 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Medium-Hard

> *The prover spoke in riddles. The verifier, patient and malicious, asked the same riddle twice—with different answers demanded. The prover, bound by determinism, revealed the secret between the contradictions.*

---

## Executive Summary

This challenge demonstrates a classical attack on interactive zero-knowledge proofs: witness extraction via verifier rewinding. When a prover responds deterministically or with predictable randomness to repeated challenges, a malicious verifier can extract the secret witness by requesting multiple transcripts with the same commitment but different challenges. This breaks the zero-knowledge property fundamentally, transforming the proof into a witness-revealing protocol.

**Flag:** *(captured and verified)*

---

## Challenge Description

The server acts as a prover in a Sigma protocol, attempting to prove knowledge of a discrete logarithm `x` such that `g^x = h`. The twist: we (the client) play the role of a malicious verifier who can choose challenges strategically to extract the witness.

**Protocol:**
1. **Prover → Verifier**: Commitment `a = g^r`
2. **Verifier → Prover**: Challenge `c`
3. **Prover → Verifier**: Response `z = r + c·x` (mod q)
4. **Verification**: Check `g^z == a · h^c`

**The Vulnerability:** If the prover reuses the same randomness `r` across multiple runs, we can extract `x` by asking for different challenges.

---

## Vulnerability Analysis

### Knowledge Extraction Attack

**Normal Execution (Honest):**
- Prover commits once, verifier sends one challenge, prover responds once
- From a single transcript `(a, c, z)`, the verifier learns nothing about `x` (assuming `r` is truly random)

**Malicious Verifier Attack:**
If the verifier can obtain two valid transcripts with the same commitment but different challenges:

```
Transcript 1: (a, c₁, z₁) where z₁ = r + c₁·x
Transcript 2: (a, c₂, z₂) where z₂ = r + c₂·x
```

**Extraction:**
```
z₁ = r + c₁·x
z₂ = r + c₂·x
―――――――――――――――――
z₁ - z₂ = (c₁ - c₂)·x

x = (z₁ - z₂) / (c₁ - c₂)  mod q
```

**Requirements for Attack:**
1. Prover uses the same `r` for both transcripts (randomness reuse)
2. Verifier can request multiple transcripts with the same commitment
3. Verifier controls the challenges `c₁` and `c₂`

---

## Exploitation

### Step 1: Rewinding the Prover

```python
#!/usr/bin/env python3
from pwn import remote
import json

conn = remote('socket.cryptohack.org', 13428)

# Receive parameters
conn.recvuntil(b'p = ')
p = int(conn.recvline())
conn.recvuntil(b'g = ')
g = int(conn.recvline())
conn.recvuntil(b'h = ')
h = int(conn.recvline())
q = (p - 1) // 2

# Round 1: Get first transcript
conn.recvuntil(b'commitment a = ')
a = int(conn.recvline())

c1 = 2  # First challenge
conn.sendline(str(c1).encode())

conn.recvuntil(b'response z = ')
z1 = int(conn.recvline())

print(f"Transcript 1: (a={a}, c={c1}, z={z1})")

# Request another proof (prover restarts with same randomness)
conn.recvuntil(b'commitment a = ')
a_second = int(conn.recvline())

assert a == a_second, "Commitment must be the same!"

c2 = 5  # Different challenge
conn.sendline(str(c2).encode())

conn.recvuntil(b'response z = ')
z2 = int(conn.recvline())

print(f"Transcript 2: (a={a_second}, c={c2}, z={z2})")
```

### Step 2: Extract the Witness

```python
# Extract x using the two transcripts
# z1 = r + c1*x  (mod q)
# z2 = r + c2*x  (mod q)
# z1 - z2 = (c1 - c2)*x  (mod q)

def modinv(a, m):
    """Modular inverse"""
    return pow(a, -1, m)

delta_z = (z1 - z2) % q
delta_c = (c1 - c2) % q

x = (delta_z * modinv(delta_c, q)) % q

print(f"\n[!] Extracted witness: x = {x}")

# Verify extraction
assert pow(g, x, p) == h, "Extraction failed!"
print("[+] Verification passed!")

# Get flag
flag = conn.recvall().decode()
print(f"\nFlag: {flag}")
```

### Complete Exploit

```python
#!/usr/bin/env python3
from pwn import remote

def modinv(a, m):
    return pow(a, -1, m)

conn = remote('socket.cryptohack.org', 13428)

# Parse parameters
conn.recvuntil(b'p = ')
p = int(conn.recvline())
conn.recvuntil(b'g = ')
g = int(conn.recvline())
conn.recvuntil(b'h = ')
h = int(conn.recvline())
q = (p - 1) // 2

# Get two transcripts with same commitment, different challenges
transcripts = []
challenges = [2, 7]

for c in challenges:
    conn.recvuntil(b'commitment a = ')
    a = int(conn.recvline())

    conn.sendline(str(c).encode())

    conn.recvuntil(b'response z = ')
    z = int(conn.recvline())

    transcripts.append((a, c, z))
    print(f"Got transcript: (a={a}, c={c}, z={z})")

# Verify same commitment
assert transcripts[0][0] == transcripts[1][0], "Commitments differ!"

# Extract witness
a1, c1, z1 = transcripts[0]
a2, c2, z2 = transcripts[1]

x = ((z1 - z2) * modinv(c1 - c2, q)) % q

# Verify
assert pow(g, x, p) == h, "Extraction failed!"

print(f"\n[+] Extracted secret: x = {x}")
print(f"[+] Verification: g^x = {pow(g, x, p)} == h = {h}")

# Receive flag
flag = conn.recvall().decode()
print(flag)
```

---

## Root Causes

1. **Deterministic or Reused Randomness**: The prover uses the same `r` across multiple proof attempts
2. **No Protection Against Rewinding**: The protocol doesn't prevent verifiers from requesting multiple transcripts
3. **Interactive Protocol**: The verifier has agency to choose challenges maliciously
4. **Special Soundness Exploited**: The protocol's "special soundness" property—extraction from two transcripts—works against an honest prover when facing a malicious verifier

---

## Remediation

### Immediate Fixes

1. **Fresh Randomness Per Run**:
   ```python
   # Each proof MUST use new, cryptographically random r
   import secrets
   r = secrets.randbelow(q)
   ```

2. **Commit to Randomness**:
   ```python
   # Hash the randomness with a timestamp/nonce
   r_commit = H(r || timestamp || session_id)
   # Ensures r cannot be reused across sessions
   ```

3. **Use Fiat-Shamir (Non-Interactive)**:
   ```python
   # Eliminate verifier agency entirely
   c = H(g, h, a, message)  # Challenge derived from commitment
   # Verifier cannot choose c, cannot rewind
   ```

4. **Session Binding**:
   ```python
   # Bind proof to session/context to prevent transcript reuse
   c = H(session_id || a || timestamp)
   ```

### Stronger Protocols

**Schnorr Signature (Non-Interactive Fiat-Shamir):**
```python
# Sign message m
r = random()
R = g^r
c = H(R || m)
s = r + c*x
# Verifier checks: g^s == R * h^c
# No rewinding possible; c is deterministic from R
```

**Commitment Schemes:**
Use a commitment scheme for `r` before computing `a` to prevent rewinding from working even in interactive settings.

---

## Key Takeaways

- **Special Soundness Cuts Both Ways**: Extractability makes proofs secure against cheating provers—but enables witness extraction by malicious verifiers
- **Randomness is Sacred**: Reusing nonces in ZK protocols is catastrophic
- **Interactive = Vulnerable**: Interactive protocols give verifiers power; Fiat-Shamir removes it
- **Honest-Verifier ZK ≠ Malicious-Verifier ZK**: Many protocols assume honest verifiers; real adversaries aren't honest

---

## Attack vs. Security Property

| Security Property | Violated | Why |
|-------------------|----------|-----|
| Zero-Knowledge | ✅ YES | Verifier extracts witness `x` |
| Soundness | ❌ NO | Honest prover still convinces verifier |
| Completeness | ❌ NO | Valid proofs still accepted |
| **Special Soundness** | ⚠️ **EXPLOITED** | Two transcripts → witness extraction |

---

## Protocol Timeline

```
[Malicious Verifier Attack]

Round 1:
V: (requests proof)
P: a = g^r
V: c₁ = 2
P: z₁ = r + 2x

Round 2 (rewind):
V: (requests same proof again)
P: a = g^r  ← SAME r!
V: c₂ = 7
P: z₂ = r + 7x

Extraction:
z₁ - z₂ = (2 - 7)x = -5x
x = (z₁ - z₂) / -5  mod q

✅ Secret extracted!
```

---

## References

- [On Σ-Protocols and Witness Extraction](https://www.win.tue.nl/~berry/CryptographicProtocols/LectureNotes.pdf)
- [Schnorr Protocol Security](https://link.springer.com/chapter/10.1007/3-540-46766-1_9)
- [Fiat-Shamir Transformation](https://link.springer.com/chapter/10.1007/3-540-47721-7_12)

---

> *The prover, naive and deterministic, repeated its riddle. We asked once, then twice, with different keys to the same lock. The answers diverged, and from their difference, the secret emerged—naked arithmetic, no zero-knowledge left. Rewinding is a weapon. Non-interactivity is armor.*
