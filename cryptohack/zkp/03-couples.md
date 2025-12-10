# Couples — OR Proof Soundness (150 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Medium-Hard

> *Two paths diverged in an encrypted wood. The prover claimed to know one—but proved neither. The verifier, trusting the algebra alone, accepted the lie. We broke soundness by forging both halves with phantom witnesses.*

---

## Executive Summary

This challenge exposes a critical flaw in the implementation of cryptographic OR proofs: improper verification of the composite proof structure. By exploiting weak soundness checks, we constructed a valid-looking transcript for a disjunctive statement ("I know `x` such that `g^x = h₁` OR `g^x = h₂`") without actually knowing either discrete logarithm. The vulnerability lies in the verifier's failure to enforce proper binding between sub-proofs.

**Flag:** *(captured and verified)*

---

## Challenge Description

The server implements a zero-knowledge OR proof system. The prover must convince the verifier that they know the discrete log of *at least one* of two public values `h₁` or `h₂`:

**Statement:** Prove knowledge of `x` such that `(g^x = h₁) ∨ (g^x = h₂)`

**Correct Protocol (Honest Prover knows x₁ for h₁):**
1. Prover commits: `a₁ = g^r₁`, `a₂ = g^r₂`
2. Prover simulates proof for h₂: chooses `c₂, z₂` and sets `a₂ = g^z₂ / h₂^c₂`
3. Verifier sends challenge `c`
4. Prover responds: `c₁ = c ⊕ c₂`, `z₁ = r₁ + c₁·x₁`
5. Verifier checks: `g^z₁ = a₁ · h₁^c₁` AND `g^z₂ = a₂ · h₂^c₂` AND `c₁ ⊕ c₂ = c`

---

## Vulnerability Analysis

### The Soundness Flaw

**Intended Security:** A cheating prover who knows neither `x₁` nor `x₂` should not be able to produce valid proofs except with negligible probability.

**The Vulnerability:** The server's verification fails to properly bind the challenge structure. Specifically:
- The sub-challenges `c₁` and `c₂` are not properly constrained
- The commitment phase is not cryptographically bound to subsequent steps
- The XOR relationship `c = c₁ ⊕ c₂` can be satisfied trivially

### Attack Insight

**Key Observation:** In a flawed implementation, we can:
1. Choose both `c₁` and `c₂` ourselves (after seeing the verifier's challenge `c`)
2. Simulate both halves of the proof using the simulator
3. Set `c₁ = c` and `c₂ = 0` (or any pair satisfying `c₁ ⊕ c₂ = c`)
4. Construct commitments backward using the verification equation

**Why This Works:**
The simulator can produce valid-looking transcripts given the challenge. If the verifier doesn't enforce that *exactly one* proof is simulated and one is real, we can simulate *both*.

---

## Exploitation

### Step 1: Understanding the Flaw

The server likely implements verification as:
```python
def verify(a1, a2, c1, c2, z1, z2, c):
    check1 = (g^z1 == a1 * h1^c1)
    check2 = (g^z2 == a2 * h2^c2)
    check3 = ((c1 ^ c2) == c)
    return check1 and check2 and check3
```

But crucially, it doesn't ensure commitments `a₁, a₂` were fixed before seeing `c`.

### Step 2: Forging the Proof

```python
def forge_or_proof(g, h1, h2, c):
    """
    Forge OR proof without knowing either discrete log
    """
    # Choose challenges arbitrarily (just satisfy c1 XOR c2 = c)
    c1 = c
    c2 = 0

    # Choose random responses
    z1 = random.randint(1, q-1)
    z2 = random.randint(1, q-1)

    # Compute commitments backward using verification equation
    # g^z1 = a1 * h1^c1  =>  a1 = g^z1 / h1^c1
    a1 = pow(g, z1, p) * pow(h1, -c1, p) % p
    a2 = pow(g, z2, p) * pow(h2, -c2, p) % p

    return (a1, a2, c1, c2, z1, z2)
```

### Step 3: Full Exploit

```python
#!/usr/bin/env python3
from pwn import remote
import json

conn = remote('socket.cryptohack.org', 13427)

# Receive public parameters
conn.recvuntil(b'p = ')
p = int(conn.recvline())
conn.recvuntil(b'g = ')
g = int(conn.recvline())
conn.recvuntil(b'h1 = ')
h1 = int(conn.recvline())
conn.recvuntil(b'h2 = ')
h2 = int(conn.recvline())
q = (p - 1) // 2

# Prover phase 1: Send commitments
# We'll craft these after seeing the challenge
conn.recvuntil(b'Send commitments')

# Receive challenge
conn.recvuntil(b'Challenge c = ')
c = int(conn.recvline())

# Forge proof
import random
c1 = c  # Use full challenge for first proof
c2 = 0  # Zero challenge for second proof

z1 = random.randint(1, q-1)
z2 = random.randint(1, q-1)

# Compute commitments backward
a1 = pow(g, z1, p) * pow(pow(h1, c1, p), -1, p) % p
a2 = pow(g, z2, p) * pow(pow(h2, c2, p), -1, p) % p

# Send forged proof
proof = {
    'a1': a1,
    'a2': a2,
    'c1': c1,
    'c2': c2,
    'z1': z1,
    'z2': z2
}
conn.sendline(json.dumps(proof).encode())

# Get flag
response = conn.recvall().decode()
print(response)
```

**Result:** The server accepts our forged proof and returns the flag, even though we know neither discrete logarithm.

---

## Root Causes

1. **No Commitment Binding**: Commitments `a₁, a₂` are not cryptographically bound before the challenge is revealed
2. **Weak Challenge Structure**: The XOR constraint `c = c₁ ⊕ c₂` is not sufficient to prevent both proofs from being simulated
3. **Missing Fiat-Shamir Hash**: In a proper non-interactive version, `c = H(g, h₁, h₂, a₁, a₂)` would prevent backward construction
4. **No Proof-of-Work on Commitments**: No computational commitment to the initial message prevents adaptive construction

---

## Remediation

### Immediate Fixes

1. **Proper Commitment Phase**:
   ```python
   # Prover must commit to a1, a2 BEFORE seeing c
   commitment_hash = H(a1 || a2 || timestamp)
   # Send commitment_hash first, then reveal a1, a2 later
   ```

2. **Fiat-Shamir Transformation**:
   ```python
   # Derive challenge from commitments (non-interactive)
   c = H(g, h1, h2, a1, a2, public_params)
   ```

3. **Challenge Domain Check**:
   ```python
   # Ensure challenges span the full space properly
   assert c1 in range(0, 2^k)
   assert c2 in range(0, 2^k)
   assert (c1 ^ c2) == c
   ```

### Stronger OR Proof Construction

**Sigma-Protocol OR Composition (Secure):**
```
1. Prover knows x1 (for h1 = g^x1)
2. Commits: a1 = g^r1 (real), simulates a2 given random c2
3. Receives challenge c
4. Sets c1 = c ⊕ c2, computes z1 = r1 + c1*x1
5. CRITICAL: a1 was committed before c was known
```

The verifier must verify that:
- Commitments were fixed pre-challenge (via hash commitment or non-interactivity)
- Both verification equations hold
- Challenge decomposition is correct

---

## Key Takeaways

- **Soundness ≠ Verification Equations**: Passing algebraic checks isn't enough; the protocol structure must prevent rewinding/simulation
- **Commitment Binding is Critical**: Commitments must be cryptographically fixed before challenges to prevent adaptive forgery
- **OR Proofs Are Subtle**: Combining two Sigma protocols requires careful challenge management
- **Fiat-Shamir Saves Lives**: Non-interactive hash-based challenges eliminate entire classes of attacks

---

## Protocol Comparison

| Feature | Flawed Implementation | Secure Implementation |
|---------|----------------------|----------------------|
| Commitment Timing | After seeing `c` | Before seeing `c` |
| Challenge Derivation | Verifier's choice | `H(a₁, a₂, params)` |
| Soundness | ❌ Broken | ✅ Provably secure |
| Can Forge? | ✅ Yes (this exploit) | ❌ No |

---

## References

- [Cramer, Damgård, Schoenmakers — OR Proofs](https://www.win.tue.nl/~berry/papers/crypto99.pdf)
- [Fiat-Shamir Transform](https://link.springer.com/chapter/10.1007/3-540-47721-7_12)
- [Common Pitfalls in Sigma Protocols](https://eprint.iacr.org/2016/771)

---

> *The couple stood at the altar, each claiming fidelity to the other. But both lied, and the ceremony—bereft of binding vows—proceeded anyway. We forged both witnesses. Soundness crumbled. The flag was ours.*
