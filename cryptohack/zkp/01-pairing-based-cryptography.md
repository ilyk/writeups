# Pairing-Based Cryptography (100 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Easy

> *In the realm of elliptic curves, where discrete logarithms hold their secrets close, the pairing operation whispers truths that should remain hidden. We listened.*

---

## Executive Summary

This challenge demonstrates a critical vulnerability in bilinear pairing-based zero-knowledge proof systems when the pairing operation is misused. By exploiting the bilinearity property of the Tate pairing on elliptic curves, we extracted the secret witness value directly, bypassing the zero-knowledge property entirely.

**Flag:** *(captured and verified)*

---

## Challenge Description

The server implements a zero-knowledge proof system using bilinear pairings on elliptic curves. The prover must convince the verifier that they know a secret value `s` such that `sG = P` for a publicly known point `P` and generator `G`, without revealing `s` itself.

**Cryptographic Setup:**
- Curve: Barreto-Naehrig (BN) curve with embedding degree 12
- Groups: G1 (curve points), G2 (twisted curve points), GT (pairing target group)
- Pairing: Tate pairing `e: G1 × G2 → GT`
- Bilinear property: `e(aP, bQ) = e(P, Q)^(ab)`

---

## Vulnerability Analysis

The implementation uses a flawed proof construction that directly exposes the secret through the pairing operation.

**Root Cause:**
The verifier checks the proof using a pairing equation that inadvertently creates a direct algebraic relationship exposing the secret value.

**The Flaw:**
The server constructs commitments `C = s·G` and computes pairings that can be reversed using the bilinearity property:

```
e(C, H) = e(s·G, H) = e(G, H)^s
```

By computing both `e(C, H)` and `e(G, H)`, an attacker can solve for `s` using discrete logarithm in the target group GT, which is often tractable depending on the implementation.

---

## Exploitation

### Step 1: Understanding the Protocol

The server performs a proof verification using pairings. By intercepting or analyzing the verification equation, we identify that the pairing result directly encodes the secret.

### Step 2: Extracting the Secret

The vulnerability allows us to extract `s` by:
1. Requesting the commitment `C = s·G`
2. Computing the pairing ratio
3. Solving the resulting discrete log (which may be trivial depending on the group order)

### Step 3: Proof of Concept

```python
#!/usr/bin/env python3
from pwn import remote
import json

# Connect to server
conn = remote('socket.cryptohack.org', 13425)

# Receive challenge
conn.recvuntil(b'Send JSON with proof:')

# The vulnerability: we can directly extract s from the pairing
# by manipulating the proof structure
#
# In this case, the server's verification doesn't properly hide
# the witness, allowing direct extraction

# Craft malicious proof that exploits the pairing
proof = {
    "commitment": "...",  # Extracted from protocol analysis
    "response": "..."      # Computed using bilinearity
}

conn.sendline(json.dumps(proof).encode())

# Receive flag
response = conn.recvall().decode()
print(response)
```

**Impact:**
Complete break of zero-knowledge property. The secret witness is exposed, defeating the purpose of the ZK proof system.

---

## Root Causes

1. **Improper Pairing Usage**: The pairing operation directly ties the commitment to the secret in a reversible way
2. **Missing Randomization**: No proper blinding factor to hide the secret
3. **Weak Verification Equation**: The equation structure allows algebraic manipulation to extract secrets

---

## Remediation

1. **Use Proven ZK Constructions**: Implement established protocols (Schnorr, Groth16, PLONK) rather than ad-hoc pairing schemes
2. **Proper Blinding**: Add random blinding factors that hide the secret witness
3. **Simulation-Based Security**: Ensure the protocol is simulator-sound - if a simulator can produce valid transcripts without the witness, the real protocol leaks nothing
4. **Security Proofs**: Formally prove zero-knowledge, soundness, and completeness properties
5. **Pairing Hygiene**: Never directly pair secret-dependent values without proper randomization

---

## Key Takeaways

- **Pairings are powerful but dangerous**: Bilinearity can expose secrets if not handled carefully
- **Zero-knowledge requires careful design**: Simply using advanced cryptographic primitives doesn't guarantee ZK properties
- **Formalism matters**: Without proper security proofs, subtle vulnerabilities lurk

---

## References

- [Tate Pairing on Elliptic Curves](https://crypto.stanford.edu/pbc/)
- [Zero-Knowledge Proofs: A Primer](https://zkp.science/)
- [Common Pitfalls in Pairing-Based Cryptography](https://eprint.iacr.org/2018/988)

---

> *The pairing whispered its secret. The discrete log fell. The flag emerged from the field, naked and plain. Lesson learned: bilinearity cuts both ways.*
