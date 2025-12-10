# Honest Verifier Zero Knowledge (30 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Easy-Medium

> *The verifier promised to be honest—to choose challenges uniformly at random, to never peek behind the curtain of randomness. Under this gentleman's agreement, the protocol reveals nothing. But what happens when the verifier lies?*

---

## Executive Summary

This challenge explores the Honest-Verifier Zero-Knowledge (HVZK) property of Sigma protocols. We demonstrate the simulator that can produce indistinguishable transcripts without knowing the witness, proving that an honest verifier learns nothing from the protocol. The key insight: if the challenge is known in advance, we can construct valid-looking proofs backward.

**Flag:** *(captured)*

---

## Challenge Description

Implement the HVZK simulator for a Schnorr-like Sigma protocol. Given access to the challenge value in advance, produce transcripts that are computationally indistinguishable from real protocol executions.

**The Protocol:**
```
Statement: Prove knowledge of x such that g^x = y (mod p)

1. Prover: a = g^r (random r)
2. Verifier: e (random challenge)
3. Prover: z = r + e·x (mod q)
4. Verify: g^z = a · y^e (mod p)
```

---

## The HVZK Property

### Definition

A protocol is Honest-Verifier Zero-Knowledge if there exists an efficient simulator S that, given the challenge e in advance, can produce transcripts (a, e, z) indistinguishable from real executions.

**Why "Honest" Verifier?**
- The simulator needs to know e before computing a
- In the real protocol, a is sent first, then e is chosen
- Only an honest verifier (choosing e randomly, independently of a) allows this

### The Simulator

**Real Execution (Prover knows x):**
```
1. Choose random r
2. Compute a = g^r
3. Receive challenge e
4. Compute z = r + e·x
5. Output (a, e, z)
```

**Simulated Execution (No witness needed):**
```
1. Receive challenge e (in advance!)
2. Choose random z
3. Compute a = g^z · y^(-e)   ← Backward construction
4. Output (a, e, z)
```

### Why Simulation Works

**Verification equation:** `g^z = a · y^e`

**Simulated a:** `a = g^z · y^(-e)`

**Check:**
```
g^z ?= a · y^e
g^z ?= (g^z · y^(-e)) · y^e
g^z ?= g^z · y^(-e+e)
g^z ?= g^z · y^0
g^z ?= g^z · 1
g^z = g^z  ✓
```

---

## Implementation

### The Simulator

```python
#!/usr/bin/env python3
"""
HVZK Simulator for Schnorr Protocol
"""
import random

def real_transcript(g, y, x, p, q):
    """
    Generate real transcript (prover knows witness x)
    """
    # Step 1: Commitment
    r = random.randint(1, q - 1)
    a = pow(g, r, p)

    # Step 2: Challenge (from verifier)
    e = random.randint(0, 2**128 - 1)

    # Step 3: Response
    z = (r + e * x) % q

    return (a, e, z)


def simulated_transcript(g, y, p, q, e=None):
    """
    Generate simulated transcript (no witness needed!)
    HVZK Simulator: knows challenge e in advance
    """
    # Step 1: Get challenge (known in advance for simulation)
    if e is None:
        e = random.randint(0, 2**128 - 1)

    # Step 2: Choose random response
    z = random.randint(1, q - 1)

    # Step 3: Compute commitment BACKWARD
    # From: g^z = a · y^e
    # Get:  a = g^z · y^(-e)
    y_inv_e = pow(y, -e, p)  # y^(-e) mod p
    a = (pow(g, z, p) * y_inv_e) % p

    return (a, e, z)


def verify_transcript(g, y, p, a, e, z):
    """
    Verify a transcript (works for both real and simulated)
    """
    lhs = pow(g, z, p)
    rhs = (a * pow(y, e, p)) % p
    return lhs == rhs


# Demo: Compare real vs simulated
print("=== HVZK Demonstration ===\n")

# Setup
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
q = (p - 1) // 2
g = 2

# Witness
x = random.randint(1, q - 1)
y = pow(g, x, p)

print(f"Public: g, p, y = g^x")
print(f"Secret: x (witness)\n")

# Generate transcripts
print("Real transcript (with witness):")
a_real, e_real, z_real = real_transcript(g, y, x, p, q)
print(f"  a = {hex(a_real)[:20]}...")
print(f"  e = {e_real}")
print(f"  z = {hex(z_real)[:20]}...")
print(f"  Valid: {verify_transcript(g, y, p, a_real, e_real, z_real)}\n")

print("Simulated transcript (NO witness!):")
a_sim, e_sim, z_sim = simulated_transcript(g, y, p, q)
print(f"  a = {hex(a_sim)[:20]}...")
print(f"  e = {e_sim}")
print(f"  z = {hex(z_sim)[:20]}...")
print(f"  Valid: {verify_transcript(g, y, p, a_sim, e_sim, z_sim)}\n")

print("[+] Both transcripts verify!")
print("[+] Simulated transcript indistinguishable from real")
print("\n→ HVZK property demonstrated")
```

---

## Key Insight: The Timing Asymmetry

```
        REAL PROTOCOL              SIMULATION
        ─────────────              ──────────

Time 1: Choose r                 Time 1: Know e (given)
        Compute a = g^r
        Send a →

Time 2: Receive e ←              Time 2: Choose z
                                         Compute a = g^z/y^e

Time 3: Compute z = r + e·x      Time 3: Output (a, e, z)
        Send z →
```

**The Catch:** In real protocol, a is fixed before e is known. The simulator cheats by computing a *after* knowing e.

**Why HVZK is "Special":** Only works if verifier chooses e randomly/independently. A malicious verifier could choose e based on a, breaking the simulation argument.

---

## Distribution Analysis

### Real Transcript Distribution

For honest execution with witness x:
- r uniform in ℤq
- a = g^r (uniform in ⟨g⟩)
- e uniform in challenge space
- z = r + e·x mod q

Since r is uniform and independent of e, z is also uniform in ℤq.

### Simulated Transcript Distribution

For simulation without witness:
- e uniform in challenge space
- z uniform in ℤq
- a = g^z · y^(-e) (determined by e, z)

**Key observation:** For any fixed e, as z ranges over ℤq, a ranges over all of ⟨g⟩.

**Result:** Both distributions are identical:
- (a, e, z) where a, z uniform, verification holds

---

## Why This Matters

### Security Implication

HVZK proves that the protocol reveals nothing to an honest verifier. But:

| Verifier Type | ZK Property | Security |
|---------------|-------------|----------|
| Honest | ✅ HVZK | Verifier learns nothing |
| Malicious | ❓ Maybe not ZK | Verifier might learn something! |

### The Gap

**HVZK ⊊ Full ZK**

A protocol can be HVZK but not ZK against malicious verifiers. The simulator assumes it gets e in advance, but a malicious verifier could:
- Choose e based on a
- Choose e non-uniformly
- Request multiple challenges for same a

---

## Practical Implications

### When HVZK Suffices

**Fiat-Shamir Transformation:**
```python
# Make protocol non-interactive
e = H(a, public_params)  # Challenge from hash

# Now verifier has no choice in e
# HVZK is sufficient for security
```

With Fiat-Shamir, the verifier cannot choose e—it's determined by the hash. HVZK is enough!

### When HVZK Is Not Enough

**Interactive protocols with malicious verifiers:**
- Chosen-challenge attacks
- Repeated execution with same commitment
- Challenge grinding

---

## Key Takeaways

1. **HVZK = Simulability Given Challenge**: If you know e first, you can fake transcripts

2. **Backward Construction**: The trick is computing a = g^z/y^e after choosing z

3. **Distribution Equality**: Real and simulated transcripts are identically distributed

4. **Limited Guarantee**: Only honest verifiers are covered; malicious ones may learn

5. **Foundation for Fiat-Shamir**: HVZK + hash-based challenges = non-interactive ZK

---

## From HVZK to Full ZK

| Property | Assumption | Simulator Power |
|----------|------------|-----------------|
| HVZK | Honest verifier | Knows challenge in advance |
| Special HVZK | Honest verifier | Knows challenge, no rewinding |
| Full ZK | Malicious verifier | Can rewind verifier |

**Upgrade Path:**
- HVZK → Full ZK: Use commitment to verifier's randomness
- HVZK → NIZK: Apply Fiat-Shamir transformation

---

## References

- [Damgård, I.: "On Σ-Protocols"](https://www.cs.au.dk/~ivan/Sigma.pdf)
- [Goldreich, O.: "Foundations of Cryptography"](https://www.wisdom.weizmann.ac.il/~oded/foc-book.html)
- [Bellare & Rogaway: "Random Oracles are Practical"](https://cseweb.ucsd.edu/~mihir/papers/ro.pdf)

---

> *The honest verifier, true to their word, chose challenges at random. And in that honesty, they learned nothing—for any transcript they saw could have been forged by a simulator who knew their random coins. HVZK: the foundation of zero-knowledge, built on the assumption of honor.*
