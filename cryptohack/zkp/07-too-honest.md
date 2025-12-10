# Too Honest — Verifier Rewinding Attack (50 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Medium

> *The prover was too honest—too willing to repeat, too eager to please. When asked twice with different demands, they answered both. From the gap between answers, the secret emerged. Honesty, in cryptography, can be a fatal flaw.*

---

## Executive Summary

This challenge demonstrates that being "too honest" in a zero-knowledge protocol can be catastrophic. When a prover responds to multiple challenges for the same commitment, the special soundness property—designed to ensure soundness—becomes a weapon for witness extraction. The flag's leet-speak hints at the irony: being "2 hon3st" makes you "tru3" (extractable).

**Flag:** *(captured)*

---

## Challenge Description

The server acts as an overly cooperative prover who will happily respond to multiple challenges for the same commitment. By exploiting this willingness, we extract the secret witness using the special soundness property of Sigma protocols.

**The Vulnerability:**
```python
# Server says:
"not convinced? I'll happily do it again!"

# The fatal mistake: same commitment, new challenge
# This enables witness extraction
```

---

## Attack Overview

### The Problem with Being Too Helpful

**Normal Protocol (Secure):**
1. Prover commits: a = g^r
2. Verifier challenges: e
3. Prover responds: z = r + e·x
4. **Done.** One commitment, one challenge, one response.

**"Too Honest" Protocol (Broken):**
1. Prover commits: a = g^r
2. Verifier challenges: e₁
3. Prover responds: z₁ = r + e₁·x
4. **Verifier asks again:** "Can I try another challenge?"
5. Prover: "Sure!" Uses same a (same r!)
6. Verifier challenges: e₂
7. Prover responds: z₂ = r + e₂·x
8. **Extraction:** x = (z₁ - z₂)/(e₁ - e₂)

---

## Mathematical Foundation

### Special Soundness (Double-Edged)

**The Good (Security):**
If a prover can answer two different challenges for the same commitment, they must know the witness. This proves soundness.

**The Bad (Attack):**
If we can GET two responses for the same commitment, we can EXTRACT the witness. This breaks zero-knowledge.

### Extraction Formula

Given two transcripts with same commitment a:
```
(a, e₁, z₁): z₁ = r + e₁·x  (mod q)
(a, e₂, z₂): z₂ = r + e₂·x  (mod q)
```

Subtract:
```
z₁ - z₂ = (e₁ - e₂)·x  (mod q)
```

Solve:
```
x = (z₁ - z₂) · (e₁ - e₂)⁻¹  (mod q)
```

---

## Exploitation

### Step-by-Step Attack

```python
#!/usr/bin/env python3
from pwn import remote
from Crypto.Util.number import inverse, long_to_bytes

def attack_too_honest_prover():
    conn = remote('socket.cryptohack.org', 13428)

    # Get public parameters
    conn.recvuntil(b'p = ')
    p = int(conn.recvline())
    conn.recvuntil(b'q = ')
    q = int(conn.recvline())
    conn.recvuntil(b'g = ')
    g = int(conn.recvline())

    # === Round 1 ===
    # Get commitment (prover uses r)
    conn.recvuntil(b'a = ')
    a = int(conn.recvline().strip(), 16)

    conn.recvuntil(b'y = ')
    y = int(conn.recvline().strip(), 16)

    # Send first challenge
    e1 = 31337
    conn.sendline(str(e1).encode())

    conn.recvuntil(b'z = ')
    z1 = int(conn.recvline().strip(), 16)

    print(f"[1] Got (a, e₁={e1}, z₁)")

    # === Round 2 ===
    # Server says "not convinced? I'll happily do it again!"

    # Get commitment again (SAME a because SAME r!)
    conn.recvuntil(b'a = ')
    a2 = int(conn.recvline().strip(), 16)

    assert a == a2, "Different commitment! Attack won't work."
    print(f"[*] Same commitment detected - randomness reused!")

    # Send different challenge
    e2 = 1337
    conn.sendline(str(e2).encode())

    conn.recvuntil(b'z = ')
    z2 = int(conn.recvline().strip(), 16)

    print(f"[2] Got (a, e₂={e2}, z₂)")

    # === Extract Witness ===
    # x = (z1 - z2) / (e1 - e2) mod q

    numerator = (z1 - z2) % q
    denominator = (e1 - e2) % q
    x = (numerator * inverse(denominator, q)) % q

    # Verify extraction
    if pow(g, x, p) == y:
        print(f"\n[+] Witness extracted successfully!")
        print(f"[+] Verified: g^x = y ✓")

        # Decode flag (witness encodes the flag)
        flag = long_to_bytes(x)
        print(f"\n[FLAG] {flag.decode()}")
    else:
        print("[-] Extraction failed")

    conn.close()

if __name__ == "__main__":
    attack_too_honest_prover()
```

---

## Why "Too Honest" Breaks ZK

### The Protocol's Expectation

A Sigma protocol assumes:
- Fresh randomness r for each proof
- One challenge per commitment
- No re-execution with same state

### The Server's Mistake

The "too honest" server:
- Reuses the same r when asked to "prove again"
- Effectively provides (a, e₁, z₁) and (a, e₂, z₂)
- Gives the attacker exactly what special soundness needs

### The Irony

**Special soundness says:** "If you can answer two challenges, you must know the witness"

**The attack says:** "If I can GET two answers, I can COMPUTE the witness"

Same property, opposite perspective!

---

## Root Causes

1. **Randomness Reuse**: Using the same r across protocol runs
2. **Eager Cooperation**: Responding to additional challenges without fresh commitment
3. **No State Tracking**: Failing to ensure one-response-per-commitment
4. **Misunderstanding ZK**: Thinking "proving again" is harmless

---

## Remediation

### Correct Implementation

```python
class SecureProver:
    def __init__(self, secret):
        self.secret = secret
        self.used_commitments = set()

    def prove(self):
        # ALWAYS fresh randomness
        r = secrets.randbelow(q)
        a = pow(g, r, p)

        # Track used commitments
        if a in self.used_commitments:
            raise SecurityError("Commitment reuse detected!")
        self.used_commitments.add(a)

        return a, r

    def respond(self, r, challenge):
        z = (r + challenge * self.secret) % q
        return z
```

### Better: Non-Interactive

```python
def prove_non_interactive(secret, g, p, q, y):
    """
    Fiat-Shamir: No second chances possible!
    """
    r = secrets.randbelow(q)
    a = pow(g, r, p)

    # Challenge from hash - deterministic!
    e = H(a, g, y, p) % q

    z = (r + e * secret) % q

    return (a, z)  # One proof, no re-execution
```

---

## Comparison: Honest vs Too Honest

| Behavior | Secure Prover | "Too Honest" Prover |
|----------|---------------|---------------------|
| Fresh r | ✅ Every time | ❌ Reused |
| Responses per commitment | 1 | Multiple |
| State tracking | ✅ Yes | ❌ No |
| Vulnerability | None | Witness extraction |

---

## Real-World Analogues

### ECDSA Nonce Reuse
- Same mathematical vulnerability
- Sony PS3 hack (2010): Single reused nonce → private key
- Bitcoin wallet thefts: Weak RNG → predictable nonces

### Session Key Reuse
- TLS: Reusing session keys enables various attacks
- WEP: IV reuse → key recovery

### The Pattern
**Reusing secret randomness = Cryptographic suicide**

---

## Key Takeaways

1. **Special Soundness is Double-Edged**: It proves security AND enables extraction

2. **One Commitment, One Response**: Never answer multiple challenges for same commitment

3. **Fresh Randomness Always**: New r for every proof, no exceptions

4. **Prefer Non-Interactive**: Fiat-Shamir eliminates the re-execution vector

5. **"Helpful" Can Be Fatal**: In cryptography, being too cooperative breaks security

---

## The Leet-Speak Message

The flag `crypto{2_hon3st_to_b3_tru3}` translates to "too honest to be true"—a double meaning:
- The prover was too honest (willing to repeat)
- The secret became "true" (extractable) because of that honesty

---

## References

- [Damgård, I.: "On Σ-Protocols"](https://www.cs.au.dk/~ivan/Sigma.pdf)
- [fail0verflow: PS3 ECDSA Vulnerability](https://www.youtube.com/watch?v=LP1t_pzxKyE)
- [RFC 6979: Deterministic DSA/ECDSA](https://datatracker.ietf.org/doc/html/rfc6979)

---

> *The prover smiled and said "ask again." The verifier, now turned attacker, asked with different words. Two answers to the same riddle, keyed differently—and from their delta, the secret emerged. Too honest to survive. In zero-knowledge, generosity is vulnerability.*
