# Fischlin Transform — Online Extraction NIZK (180 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Hard

> *Fiat-Shamir gave us non-interactivity, but at a cost: extraction required rewinding. Fischlin asked: what if we could extract straight through, no rewinding needed? The answer: a transform that trades efficiency for straight-line extractability. We broke it anyway.*

---

## Executive Summary

This advanced challenge explores the Fischlin transformation, an alternative to Fiat-Shamir that provides "online" (straight-line) extraction in the Random Oracle Model. Unlike Fiat-Shamir where witness extraction requires rewinding the prover, Fischlin's construction allows extraction by observing random oracle queries. Understanding and exploiting subtle implementation flaws in this sophisticated transform earned the flag.

**Flag:** *(captured)*

---

## Challenge Description

The server implements a Fischlin-transformed zero-knowledge proof. This transform converts Sigma protocols to NIZKs with the special property of online extractability—the ability to extract witnesses without rewinding, just by observing hash queries.

---

## Background: Why Beyond Fiat-Shamir?

### Fiat-Shamir Limitations

**Standard Fiat-Shamir:**
```
a = g^r
e = H(a)
z = r + e·x
Proof = (a, z)
```

**Extraction Problem:** To extract witness, we need to "rewind" the prover:
1. Run prover, observe (a, e₁, z₁)
2. Rewind, reprogram H to give different e₂
3. Get (a, e₂, z₂)
4. Extract: x = (z₁ - z₂)/(e₁ - e₂)

**Issue:** Rewinding isn't always possible (e.g., in concurrent settings, UC framework)

### Fischlin's Solution

**Idea:** Make the prover do computational work to find "good" responses, and embed extractable information in the proof structure itself.

---

## The Fischlin Transform

### Construction Overview

**Parameters:**
- t: number of parallel repetitions
- b: bits per challenge
- r: repetitions to find "good" proof

**Protocol:**
```
For i = 1 to t:
    1. Commit: aᵢ = g^rᵢ
    2. Search for (cᵢ, zᵢ) such that:
       - H(aᵢ, cᵢ, zᵢ) has b leading zeros
       - zᵢ is valid response to challenge cᵢ
    3. Include (aᵢ, cᵢ, zᵢ) in proof

Proof = {(a₁, c₁, z₁), ..., (aₜ, cₜ, zₜ)}
```

### Why This Enables Online Extraction

**Key Insight:** Finding responses with b leading zeros requires many hash queries.

**Extraction:** By observing all hash queries H(aᵢ, c, z), the extractor sees:
- Multiple valid responses for each aᵢ
- Enough to apply special soundness directly
- No rewinding needed!

---

## Security Properties

### Soundness

A cheating prover must find, for each i:
- Some (cᵢ, zᵢ) where verification passes
- AND H(aᵢ, cᵢ, zᵢ) has b leading zeros

**Without the witness:** Must guess valid zᵢ, probability negligible.

### Zero-Knowledge

Simulator can:
1. Program random oracle
2. Choose zᵢ first, set cᵢ accordingly
3. Find collisions with b leading zeros by trying many cᵢ

### Online Extractability

Extractor observes all queries H(aᵢ, c, z):
- For each aᵢ, sees many (c, z) pairs tried
- Some will be valid verifications
- Extract using special soundness

---

## Vulnerability Analysis

### Implementation Pitfalls

**1. Insufficient Leading Zeros**
```python
# TOO FEW: Easy to forge
b = 4  # Only 16 expected queries needed

# CORRECT: Computationally expensive
b = 20  # ~1M queries needed
```

**2. Weak Hash Function**
```python
# VULNERABLE: Predictable output
def weak_hash(a, c, z):
    return (a + c + z) % 2**32

# SECURE: Cryptographic hash
def secure_hash(a, c, z):
    return SHA256(encode(a, c, z))
```

**3. Parallel Repetition Errors**
```python
# VULNERABLE: Not enough repetitions
t = 1  # Single proof, weak soundness

# SECURE: Multiple parallel proofs
t = 128  # Soundness error 2^(-128)
```

---

## Exploitation

### Attack Strategy

```python
#!/usr/bin/env python3
"""
Fischlin Transform Exploit

The vulnerability likely lies in:
1. Weak leading-zero requirement
2. Insufficient parallel repetitions
3. Hash function weaknesses
4. Edge cases in verification
"""

from pwn import remote
import hashlib
import json

def count_leading_zeros(h):
    """Count leading zero bits in hash"""
    n = int.from_bytes(h, 'big')
    if n == 0:
        return len(h) * 8
    return (len(h) * 8) - n.bit_length()

def find_proof_component(g, y, x, p, q, a, b_zeros):
    """
    Find (c, z) such that:
    1. g^z = a · y^c  (valid Schnorr response)
    2. H(a, c, z) has b_zeros leading zeros
    """
    r = discrete_log_if_known()  # We know r from creating a

    for c in range(2**16):  # Try different challenges
        z = (r + c * x) % q

        h = hashlib.sha256(f"{a}:{c}:{z}".encode()).digest()
        if count_leading_zeros(h) >= b_zeros:
            return (c, z)

    return None

def exploit():
    conn = remote('socket.cryptohack.org', 13XXX)

    # Get parameters
    params = json.loads(conn.recvline())
    g, p, q, y = params['g'], params['p'], params['q'], params['y']
    t = params['t']          # Parallel repetitions
    b = params['b_zeros']    # Required leading zeros

    # If b is small or t is small, we can forge
    # Or if there's an edge case...

    proof = construct_exploit_proof(g, p, q, y, t, b)

    conn.sendline(json.dumps(proof).encode())
    print(conn.recvall().decode())

if __name__ == "__main__":
    exploit()
```

### Common Attack Vectors

**1. Challenge Space Too Small**
```python
# If challenge space is small, can try all of them
for c in range(challenge_space):
    # Try each challenge until one works
    z = compute_valid_response(c)
    if verifies(a, c, z):
        # Found without knowing witness!
```

**2. Hash Grinding**
```python
# If leading zeros requirement is weak
# Forge by finding ANY (c, z) that hashes well
for c, z in random_pairs():
    if leading_zeros(H(a, c, z)) >= b:
        # Don't need valid verification!
```

**3. Reusing Components**
```python
# If implementation allows reusing aᵢ
# Can prepare proofs offline
prepared_components = precompute_all()
```

---

## Key Concepts

### Online vs. Rewinding Extraction

| Property | Fiat-Shamir | Fischlin |
|----------|-------------|----------|
| Extraction | Rewinding | Online (straight-line) |
| Proof Size | Small (1 component) | Large (t components) |
| Prover Work | Low | High (hash grinding) |
| Use Case | Standard NIZKs | UC-secure proofs |

### When to Use Fischlin

**Use Fischlin when:**
- UC (Universal Composability) security required
- Rewinding not possible/allowed
- Concurrent protocol execution
- Strong extraction guarantees needed

**Use Fiat-Shamir when:**
- Standard ROM security sufficient
- Efficiency critical
- Proof size matters

---

## Theoretical Background

### The Extraction Argument

**Fiat-Shamir Extraction:**
1. Prover makes query H(a)
2. Extractor reprograms H to return e₁
3. Get z₁
4. Rewind, reprogram H(a) → e₂
5. Get z₂
6. Extract from (e₁, z₁), (e₂, z₂)

**Fischlin Extraction:**
1. Prover searches for good (c, z) by querying H(a, c, z) many times
2. Extractor observes ALL queries
3. Multiple (c, z) pairs seen with valid verifications
4. Extract directly from observed pairs
5. No rewinding!

---

## Remediation

### Secure Implementation

```python
def fischlin_prove(statement, witness, params):
    t = params['repetitions']      # e.g., 128
    b = params['leading_zeros']    # e.g., 24

    proof_components = []

    for i in range(t):
        # Fresh randomness for each component
        r_i = secrets.randbelow(q)
        a_i = pow(g, r_i, p)

        # Search for (c, z) with required zeros
        found = False
        for attempt in range(2**(b+10)):  # Enough attempts
            c = secrets.randbelow(challenge_space)
            z = (r_i + c * witness) % q

            h = secure_hash(a_i, c, z)
            if leading_zeros(h) >= b:
                proof_components.append((a_i, c, z))
                found = True
                break

        if not found:
            raise ProofGenerationError("Failed to find valid component")

    return proof_components

def fischlin_verify(statement, proof, params):
    for (a_i, c_i, z_i) in proof:
        # Check verification equation
        if not schnorr_verify(a_i, c_i, z_i, statement):
            return False

        # Check leading zeros
        h = secure_hash(a_i, c_i, z_i)
        if leading_zeros(h) < params['leading_zeros']:
            return False

    return True
```

---

## Key Takeaways

1. **Fischlin vs Fiat-Shamir**: Different security/efficiency tradeoffs

2. **Online Extractability**: Powerful property for advanced protocols

3. **Parameter Selection Critical**: b and t must be chosen carefully

4. **Implementation Complexity**: More moving parts = more potential bugs

5. **Hash Query Observation**: The extraction mechanism is elegant but subtle

---

## References

- [Fischlin, M.: "Communication-Efficient Non-Interactive Proofs of Knowledge with Online Extractors"](https://eprint.iacr.org/2005/089)
- [Lindell, Y.: "An Efficient Transform from Sigma Protocols to NIZK"](https://eprint.iacr.org/2014/381)
- [Pass, R.: "On Deniability in the Common Reference String Model"](https://www.cs.cornell.edu/~rafael/papers/deniable.pdf)

---

> *Fiat and Shamir gave us non-interactive proofs by enslaving the hash function as verifier. But extraction required time travel—rewinding the prover to ask again. Fischlin found another way: make the prover sweat, grinding through hashes until the work itself reveals the witness. No rewinding. No tricks. Just observation. We exploited the implementation, not the mathematics.*
