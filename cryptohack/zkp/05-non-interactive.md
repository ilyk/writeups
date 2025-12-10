# Non-Interactive — Fiat-Shamir Transformation (35 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Easy-Medium

> *The verifier was dismissed. In their place, a hash function—deterministic, incorruptible, unhackable. The challenge now comes from the commitment itself, and the prover speaks to the void. This is non-interactive zero-knowledge: proofs without conversation.*

---

## Executive Summary

This challenge demonstrates the Fiat-Shamir transformation, which converts interactive Sigma protocols into non-interactive proofs. By replacing the verifier's random challenge with a hash of the commitment, we eliminate the need for interaction while preserving security. The flag hints at the relationship: SHVZK + Special Soundness → NIZK.

**Flag:** *(captured)*

---

## Challenge Description

Transform an interactive Sigma protocol into a non-interactive zero-knowledge proof using the Fiat-Shamir heuristic. The challenge is computed as a hash of the commitment, eliminating the verifier's role in challenge generation.

---

## The Fiat-Shamir Transformation

### From Interactive to Non-Interactive

**Interactive Protocol:**
```
Prover                          Verifier
──────                          ────────
a = g^r          ────→
                 ←────          e (random)
z = r + e·x      ────→
                                Check: g^z = a·y^e
```

**Non-Interactive (Fiat-Shamir):**
```
Prover
──────
a = g^r
e = H(a, public_params)    ← Hash replaces verifier!
z = r + e·x

Proof = (a, z)             ────→  Anyone can verify
```

### Why It Works

**Key Insight:** The hash function acts as a "random oracle"—it behaves like a truly random function that the prover cannot predict or control.

**Security Argument:**
1. **SHVZK**: Protocol is zero-knowledge against honest (random-challenge) verifiers
2. **Hash = Random Oracle**: H behaves like a random challenge generator
3. **Non-Interactive**: Challenge is deterministic, so no interaction needed
4. **Special Soundness**: Extracting two challenges for same commitment requires finding hash collision

---

## Implementation

### Non-Interactive Schnorr Proof

```python
#!/usr/bin/env python3
"""
Fiat-Shamir Transformation: Interactive → Non-Interactive
"""
import hashlib
import random
from Crypto.Util.number import getPrime

def hash_to_challenge(a, g, y, p, additional_data=b''):
    """
    Fiat-Shamir: Derive challenge from commitment
    """
    h = hashlib.sha256()
    h.update(str(a).encode())
    h.update(str(g).encode())
    h.update(str(y).encode())
    h.update(str(p).encode())
    h.update(additional_data)
    return int.from_bytes(h.digest(), 'big')


def create_nizk_proof(g, y, x, p, q, message=b''):
    """
    Create non-interactive proof of knowledge of x where g^x = y
    """
    # Step 1: Commitment (same as interactive)
    r = random.randint(1, q - 1)
    a = pow(g, r, p)

    # Step 2: Challenge from HASH (Fiat-Shamir)
    e = hash_to_challenge(a, g, y, p, message) % q

    # Step 3: Response (same as interactive)
    z = (r + e * x) % q

    # Proof is just (a, z) - challenge can be recomputed
    return (a, z)


def verify_nizk_proof(g, y, p, q, proof, message=b''):
    """
    Verify non-interactive proof
    """
    a, z = proof

    # Recompute challenge from hash
    e = hash_to_challenge(a, g, y, p, message) % q

    # Verify: g^z = a · y^e
    lhs = pow(g, z, p)
    rhs = (a * pow(y, e, p)) % p

    return lhs == rhs


# Demo
print("=== Non-Interactive ZK Proof (Fiat-Shamir) ===\n")

# Setup (using safe prime)
q = getPrime(256)
p = 2 * q + 1
g = 2

# Witness
x = random.randint(1, q - 1)
y = pow(g, x, p)

print(f"Public: y = g^x mod p")
print(f"Secret: x (witness)\n")

# Create proof
proof = create_nizk_proof(g, y, x, p, q, b"test message")
print(f"Proof created:")
print(f"  a = {hex(proof[0])[:30]}...")
print(f"  z = {hex(proof[1])[:30]}...\n")

# Verify proof (anyone can do this!)
valid = verify_nizk_proof(g, y, p, q, proof, b"test message")
print(f"Verification: {'✓ Valid' if valid else '✗ Invalid'}")

# Demonstrate non-interactivity
print("\n[+] No interaction required!")
print("[+] Proof can be verified by anyone, anytime")
print("[+] Challenge derived deterministically from commitment")
```

---

## Security Analysis

### Why Special Soundness Matters

**Claim:** If the underlying protocol has special soundness, Fiat-Shamir is sound.

**Intuition:**
- To cheat, prover needs two valid responses for the same commitment
- This requires two different challenges for the same a
- Different challenges = different hash outputs for same input = impossible (hash collision)

**Formal:** In the Random Oracle Model, finding (a, e₁, z₁) and (a, e₂, z₂) with e₁ ≠ e₂ requires finding a hash collision.

### Why SHVZK Matters

**Claim:** If the protocol is SHVZK, Fiat-Shamir preserves zero-knowledge.

**Intuition:**
- SHVZK simulator can create valid transcripts given challenge in advance
- In Fiat-Shamir, challenge is H(a)—determined by commitment
- Simulator can: choose a, compute e = H(a), then use SHVZK to complete

**Result:** SHVZK + Special Soundness + Random Oracle → NIZK

---

## The Random Oracle Model

### What Is It?

The random oracle is a theoretical construct:
- A truly random function H: {0,1}* → {0,1}^n
- For new input x, output H(x) is uniformly random
- For repeated input, output is consistent

### In Practice

We instantiate with hash functions (SHA-256, BLAKE2, etc.):
```python
# Theoretical
H(x) = truly random output

# Practical
H(x) = SHA256(x)
```

### The ROM Controversy

**Pro:** Enables simple, efficient proofs
**Con:** Real hash functions aren't random oracles

**Practical stance:** No known attacks on well-designed Fiat-Shamir constructions with standard hash functions.

---

## Common Pitfalls

### ❌ Forgetting Public Parameters

```python
# WRONG: Only hash commitment
e = H(a)  # Attacker can reuse proof for different y!

# RIGHT: Include all public parameters
e = H(a, g, y, p, context)
```

### ❌ Missing Message Binding

```python
# WRONG: Signature without message
e = H(a, g, y, p)  # Proof not bound to any message

# RIGHT: Include message for signatures
e = H(a, g, y, p, message)  # Now it's a signature on message
```

### ❌ Weak Hash Function

```python
# WRONG: Truncated or weak hash
e = H(a) % 256  # Only 8 bits of challenge!

# RIGHT: Full hash output
e = H(a)  # 256 bits of challenge
```

---

## From NIZK to Digital Signatures

The Fiat-Shamir transformation is exactly how Schnorr signatures work:

**Schnorr Signature (sign message m):**
```python
def sign(m, x, g, p, q):
    r = random.randint(1, q-1)
    R = pow(g, r, p)

    # Fiat-Shamir: hash commitment AND message
    e = H(R, g, y, m) % q

    s = (r + e * x) % q
    return (R, s)

def verify(m, sig, y, g, p, q):
    R, s = sig
    e = H(R, g, y, m) % q
    return pow(g, s, p) == (R * pow(y, e, p)) % p
```

**Result:** A Schnorr signature is a NIZK proof of knowledge of the private key, bound to a message.

---

## Comparison: Interactive vs Non-Interactive

| Property | Interactive | Non-Interactive |
|----------|-------------|-----------------|
| Communication | 3 messages | 1 message (proof) |
| Verifier Role | Chooses challenge | None (derives from hash) |
| Timing | Synchronous | Asynchronous |
| Reusability | Single verifier | Anyone can verify |
| Security Model | Standard | Random Oracle |
| Use Cases | Limited | Signatures, blockchain, etc. |

---

## Real-World Applications

### 1. Digital Signatures
- **Schnorr**: Bitcoin (BIP-340), EdDSA
- **ECDSA**: Widely deployed (can be viewed as Fiat-Shamir on a related protocol)

### 2. Blockchain Proofs
- **zk-SNARKs**: Use Fiat-Shamir for non-interactivity
- **zk-STARKs**: Hash-based, inherently non-interactive

### 3. Authentication
- **Challenge-Response → Token**: Transform login protocols to bearer tokens

### 4. Credential Systems
- **Anonymous Credentials**: Prove attributes without interaction

---

## Key Takeaways

1. **Fiat-Shamir = Hash as Verifier**: Replace random challenge with H(commitment)

2. **Prerequisites**: Underlying protocol must be SHVZK + Specially Sound

3. **ROM Security**: Proofs are in Random Oracle Model (hash = random function)

4. **Hash Everything Public**: Include ALL public parameters and context in hash

5. **Foundation of Modern Crypto**: Schnorr signatures, zk-SNARKs, and more

---

## References

- [Fiat & Shamir: "How To Prove Yourself"](https://link.springer.com/chapter/10.1007/3-540-47721-7_12)
- [Bellare & Rogaway: "Random Oracles are Practical"](https://cseweb.ucsd.edu/~mihir/papers/ro.pdf)
- [BIP-340: Schnorr Signatures for Bitcoin](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)

---

> *The verifier stepped aside. In their place stood a hash—immutable, impartial, incorruptible. The prover now speaks to mathematics itself, and mathematics answers with a challenge derived from the prover's own words. Non-interactive zero-knowledge: proof without dialogue, trust without presence.*
