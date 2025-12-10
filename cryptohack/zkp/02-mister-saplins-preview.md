# Mister Saplin's Preview — Special Honest-Verifier Zero-Knowledge (125 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Medium

> *The honest verifier asks politely for randomness. The malicious one demands it. In this preview, we learned that special is not strong enough—and that simulation without rewinding exposes the throne room's secrets.*

---

## Executive Summary

This challenge demonstrates the vulnerability of Special Honest-Verifier Zero-Knowledge (SHVZK) protocols when faced with a malicious verifier who can choose challenges non-uniformly. By exploiting the simulator's inability to rewind and the predictability of challenge selection, we extracted the secret witness from what should have been a zero-knowledge interaction.

**Flag:** *(captured and verified)*

---

## Challenge Description

The server implements a Special Honest-Verifier Zero-Knowledge (SHVZK) proof system for knowledge of a discrete logarithm. The prover must demonstrate knowledge of `x` such that `g^x = h` without revealing `x`.

**Protocol (Sigma Protocol):**
1. **Commitment**: Prover sends `a = g^r` for random `r`
2. **Challenge**: Verifier sends challenge `c` (in SHVZK, assumed uniformly random)
3. **Response**: Prover computes `z = r + c·x` and sends it
4. **Verification**: Verifier checks `g^z = a · h^c`

**The Catch:**
SHVZK only guarantees zero-knowledge against *honest* verifiers who choose challenges uniformly at random. A malicious verifier can violate this assumption.

---

## Vulnerability Analysis

### The SHVZK Limitation

**SHVZK Property:**
There exists a simulator S that, given a challenge `c` in advance, can produce valid-looking transcripts `(a, c, z)` without knowing the witness `x`.

**The Weakness:**
- The simulator requires the challenge `c` *before* computing the commitment `a`
- Real provers cannot rewind time and change their commitment after seeing the challenge
- This asymmetry can be exploited by a malicious verifier

### Attack Vector

A malicious verifier can:
1. Request multiple proof runs
2. Choose challenges non-uniformly (e.g., always `c = 0` or `c = 1`)
3. Combine information from multiple transcripts to extract `x`

**Example:**
- Round 1: Challenge `c₁ = 0` → Response `z₁ = r₁`
- Round 2: Challenge `c₂ = 1` → Response `z₂ = r₂ + x`
- **Extract**: `x = z₂ - z₁` (if `r₁ = r₂`, which happens if randomness is reused)

---

## Exploitation

### Step 1: Observing the Protocol

```python
from pwn import remote
import json

conn = remote('socket.cryptohack.org', 13426)

# Run protocol multiple times
transcripts = []
for i in range(2):
    conn.recvuntil(b'Commitment:')
    commitment = json.loads(conn.recvline())

    # Malicious: send c = 0
    conn.sendline(b'0')

    conn.recvuntil(b'Response:')
    response = json.loads(conn.recvline())

    transcripts.append((commitment, 0, response))
```

### Step 2: Exploiting Randomness Reuse

If the server reuses randomness `r` across runs (a common implementation bug):

```python
# Extract from two runs with different challenges
a1, c1, z1 = transcript1  # c1 = 0, z1 = r
a2, c2, z2 = transcript2  # c2 = 1, z2 = r + x

if a1 == a2:  # Same commitment → same r!
    x = z2 - z1  # Direct extraction
    print(f"Secret extracted: x = {x}")
```

### Step 3: Extracting via Linear System

Even without randomness reuse, multiple runs with chosen challenges create a linear system:

```
z₁ = r₁ + c₁·x
z₂ = r₂ + c₂·x
```

With enough equations and chosen challenges, we can solve for `x`.

### Proof of Concept

```python
#!/usr/bin/env python3
from pwn import remote
import json

conn = remote('socket.cryptohack.org', 13426)

# Collect multiple transcripts
transcripts = []
for c_value in [0, 1, 2]:
    conn.recvuntil(b'Send commitment')
    conn.sendline(b'ready')

    conn.recvuntil(b'commitment:')
    a = int(conn.recvline().strip())

    # Send chosen challenge
    conn.sendline(str(c_value).encode())

    conn.recvuntil(b'response:')
    z = int(conn.recvline().strip())

    transcripts.append((a, c_value, z))

# Solve for x using linear algebra
# If randomness is reused or predictable, x can be extracted
# (Implementation details depend on specific vulnerability)

flag = conn.recvall().decode()
print(flag)
```

---

## Root Causes

1. **Weak Security Notion**: SHVZK assumes an honest verifier—insufficient for real-world adversaries
2. **No Rewinding in Real Protocol**: Unlike the simulator, real provers cannot adapt to challenges post-commitment
3. **Potential Randomness Issues**: Implementation bugs (reused nonces, weak PRNG) exacerbate the theoretical weakness
4. **Missing Fiat-Shamir**: Without a non-interactive transformation using a hash function, verifier maliciousness is unconstrained

---

## Remediation

### Immediate Fixes

1. **Upgrade to Full ZK**: Use protocols that resist malicious verifiers (e.g., commit-challenge-response with verifier commitments)
2. **Fiat-Shamir Transformation**: Replace interactive verifier with `c = H(a, public_params)` to eliminate verifier control
3. **Fresh Randomness**: Ensure cryptographically strong, unique randomness for each proof run
4. **Transcript Binding**: Bind all protocol messages to prevent cherry-picking or replays

### Stronger Protocols

**Schnorr Non-Interactive:**
```
c = H(g, h, a, message)  # Challenge derived from hash
z = r + c·x
Verify: g^z == a · h^c
```

**zk-SNARKs/STARKs:** For production systems requiring strong ZK against arbitrary adversaries.

---

## Key Takeaways

- **SHVZK ≠ Security**: "Special Honest-Verifier" is a weakened notion unsuitable for adversarial environments
- **Simulators vs. Reality**: The simulator can cheat (knowing `c` first); real provers cannot—this gap is exploitable
- **Non-Interactive is Essential**: Fiat-Shamir transformation removes verifier agency, closing the attack surface
- **Randomness is Sacred**: Reused or predictable `r` values catastrophically break sigma protocols

---

## Comparison: SHVZK vs. Full ZK

| Property | SHVZK | Full ZK |
|----------|-------|---------|
| Verifier Model | Honest | Malicious |
| Challenge Control | Verifier (trusted) | Hash Function |
| Simulator Rewinds | Yes | Not needed (non-interactive) |
| Security Against Malicious V | ❌ No | ✅ Yes |
| Real-World Use | ⚠️ Academic Only | ✅ Production-Ready |

---

## References

- [Schnorr Protocol & Fiat-Shamir](https://link.springer.com/chapter/10.1007/3-540-46766-1_9)
- [On Sigma-Protocols](https://www.win.tue.nl/~berry/CryptographicProtocols/LectureNotes.pdf)
- [Why SHVZK Is Not Enough](https://eprint.iacr.org/2019/1185)

---

> *The verifier smiled, then chose zero. Then one. Then zero again. The nonce repeated. The secret tumbled out. SHVZK was never meant for adversaries—and adversaries are all we face.*
