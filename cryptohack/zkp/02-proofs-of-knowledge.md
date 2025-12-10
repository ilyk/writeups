# Proofs of Knowledge — Sigma Protocol Implementation (5 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Tutorial

> *In the beginning, there was the commitment. Then came the challenge. Finally, the response—and with it, the proof that knowledge exists without revelation. This is the foundation upon which all zero-knowledge rests.*

---

## Executive Summary

This introductory challenge requires implementing a basic Sigma protocol (Schnorr's protocol) for proving knowledge of a discrete logarithm. While straightforward, it establishes the fundamental three-move structure that underpins most zero-knowledge proof systems: **Commit-Challenge-Response**.

**Flag:** *(captured)*

---

## Challenge Description

Implement a proof of knowledge for the discrete logarithm problem:

**Statement:** Prove knowledge of `w` such that `g^w ≡ y (mod p)` without revealing `w`.

**Protocol Requirements:**
1. Generate random nonce `r`
2. Compute commitment `a = g^r mod p`
3. Receive challenge `e` from verifier
4. Compute response `z = r + e·w mod q`
5. Verifier checks: `g^z ≡ a · y^e (mod p)`

---

## Cryptographic Background

### The Sigma Protocol Structure

**Name Origin:** The three-message flow resembles the Greek letter Sigma (Σ)

**Protocol Flow:**
```
Prover (knows w)              Verifier
─────────────────            ──────────
Choose r ← ℤq
Compute a = g^r
                  ─── a ───→
                            Choose e ← ℤ_challenge
                  ←── e ────
Compute z = r + ew
                  ─── z ───→
                            Verify: g^z ?= a·y^e
```

**Security Properties:**
- **Completeness**: Honest prover always convinces honest verifier
- **Soundness**: Cheating prover (without witness) fails except with negligible probability
- **Zero-Knowledge**: Verifier learns nothing beyond validity of the statement

---

## Implementation

### Correct Protocol Implementation

```python
#!/usr/bin/env python3
from Crypto.Util.number import getPrime, inverse
import random

class SchnorrProtocol:
    def __init__(self, bitsize=512):
        """Initialize protocol parameters"""
        # Generate prime p such that q = (p-1)/2 is also prime
        while True:
            q = getPrime(bitsize)
            p = 2*q + 1
            if isPrime(p):
                break

        # Find generator g of order q
        while True:
            h = random.randint(2, p-2)
            g = pow(h, 2, p)
            if g != 1:
                break

        self.p = p
        self.q = q
        self.g = g

    def prover_commit(self, w):
        """
        Prover: Generate commitment
        Input: w (witness/secret)
        Output: (a, r) where a is commitment, r is randomness
        """
        # Sample random nonce
        r = random.randint(0, self.q - 1)

        # Compute commitment
        a = pow(self.g, r, self.p)

        return a, r

    def prover_respond(self, r, e, w):
        """
        Prover: Compute response
        Input: r (nonce), e (challenge), w (witness)
        Output: z (response)
        """
        # z = r + e*w  (mod q)
        z = (r + e * w) % self.q
        return z

    def verifier_verify(self, a, e, z, y):
        """
        Verifier: Check proof
        Input: a (commitment), e (challenge), z (response), y (public value)
        Output: True if proof valid, False otherwise
        """
        # Check: g^z ≡ a * y^e  (mod p)
        lhs = pow(self.g, z, self.p)
        rhs = (a * pow(y, e, self.p)) % self.p

        return lhs == rhs

# Example usage
protocol = SchnorrProtocol(512)

# Setup: Prover knows secret w, published y = g^w
w = random.randint(1, protocol.q - 1)
y = pow(protocol.g, w, protocol.p)

# Protocol execution
a, r = protocol.prover_commit(w)
e = random.randint(0, 2**128 - 1)  # Verifier's challenge
z = protocol.prover_respond(r, e, w)

# Verification
assert protocol.verifier_verify(a, e, z, y)
print("✓ Protocol verification passed")
print("Flag received!")
```

---

## Key Concepts

### 1. Commitment Phase
The prover chooses random `r` and computes `a = g^r`. This commitment **binds** the prover to a specific randomness without revealing `w`.

**Critical Property:** The commitment must be sent before the challenge. Otherwise, the prover could adaptively choose `r` after seeing `e`, trivially satisfying the verification equation.

### 2. Challenge Phase
The verifier sends a random challenge `e`. In interactive protocols, this prevents the prover from pre-computing valid transcripts.

**Insight:** The unpredictability of `e` forces the prover to "know" `w` rather than just having a pre-computed proof.

### 3. Response Phase
The prover computes `z = r + e·w mod q`. This response is information-theoretically binding to both `r` and `w`.

**Why This Works:**
```
g^z = g^(r + e·w)
    = g^r · g^(e·w)
    = a · (g^w)^e
    = a · y^e  ✓
```

---

## Security Analysis

### Completeness

**Claim:** An honest prover with witness `w` always convinces the verifier.

**Proof:**
```
Honest prover computes:
  a = g^r
  z = r + e·w

Verifier checks:
  g^z = g^(r + e·w) = g^r · g^(e·w) = a · (g^w)^e = a · y^e  ✓
```

### Special Soundness

**Claim:** Given two accepting transcripts `(a, e₁, z₁)` and `(a, e₂, z₂)` with `e₁ ≠ e₂`, we can extract the witness `w`.

**Extraction:**
```
z₁ = r + e₁·w  (mod q)
z₂ = r + e₂·w  (mod q)
────────────────────────
z₁ - z₂ = (e₁ - e₂)·w  (mod q)

w = (z₁ - z₂) · (e₁ - e₂)^(-1)  (mod q)
```

### Honest-Verifier Zero-Knowledge

**Claim:** A simulator can produce indistinguishable transcripts without knowing `w`.

**Simulator (knows `e` in advance):**
```
1. Choose random z ← ℤq
2. Compute a = g^z · y^(-e)  mod p
3. Output (a, e, z)
```

**Verification:** `g^z ≡ a · y^e` holds by construction.

---

## Common Implementation Pitfalls

### ❌ Incorrect: Using Addition Instead of Modular Arithmetic
```python
# WRONG: z = r + e * w  (no modulo)
z = r + e * w  # May overflow, leak information
```

### ✅ Correct: Proper Modular Arithmetic
```python
# RIGHT: z = (r + e * w) mod q
z = (r + e * w) % q
```

### ❌ Incorrect: Reusing Randomness
```python
# WRONG: Global r used for all proofs
r = random.randint(0, q-1)
for proof in proofs:
    a = pow(g, r, p)  # Same r!
    # ... witness can be extracted
```

### ✅ Correct: Fresh Randomness Per Proof
```python
# RIGHT: New r for each proof
for proof in proofs:
    r = random.randint(0, q-1)  # Fresh!
    a = pow(g, r, p)
```

---

## Why This Matters

### Foundation of Modern ZK Systems

The Sigma protocol is the building block for:
- **zk-SNARKs**: Groth16, PLONK use sigma-like structures
- **Digital Signatures**: Schnorr signatures are Fiat-Shamir transformed sigma protocols
- **Anonymous Credentials**: Ring signatures, group signatures
- **Blockchain Privacy**: Monero, Zcash transaction proofs

### Real-World Applications

**Bitcoin Schnorr Signatures (BIP-340):**
```python
# Non-interactive version using Fiat-Shamir
e = H(R || P || m)  # Challenge from hash
s = r + e·x         # Response (same structure!)
Verify: g^s = R · P^e
```

**Ethereum ZK-Rollups:**
Uses sigma protocol composition to batch-verify thousands of transactions off-chain.

---

## Key Takeaways

1. **Three-Move Structure is Universal**: Commit-Challenge-Response appears everywhere in ZK
2. **Randomness is Sacred**: Fresh, unpredictable `r` for each execution
3. **Modular Arithmetic Matters**: Always reduce modulo the group order
4. **Special Soundness**: Two transcripts → witness extraction (this is a feature AND a vulnerability)
5. **Building Block**: Master the sigma protocol to understand all advanced ZK systems

---

## From Interactive to Non-Interactive

This challenge uses an interactive verifier. The next step (Fiat-Shamir) converts this to non-interactive:

**Interactive (this challenge):**
```
Prover → Verifier: a
Verifier → Prover: e (random)
Prover → Verifier: z
```

**Non-Interactive (Fiat-Shamir):**
```
Prover computes: e = H(a, public_params)
Prover sends: (a, z)
Verifier recomputes: e = H(a, public_params), checks g^z = a·y^e
```

---

## References

- [Schnorr, C.P.: "Efficient Signature Generation by Smart Cards"](https://link.springer.com/article/10.1007/BF00196725)
- [Damgård, I.: "On Σ-Protocols"](https://www.cs.au.dk/~ivan/Sigma.pdf)
- [BIP-340: Schnorr Signatures for Bitcoin](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

---

> *The first sigma was simple. A commitment. A challenge. A response. Three messages that prove knowledge without revealing secrets. From this foundation, towers of cryptographic proof systems rise—but they all echo this elegant dance. Master the sigma, and you master the foundation.*
