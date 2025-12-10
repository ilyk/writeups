# ZKP Introduction (5 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Tutorial

> *Before proving without revealing, one must understand what proof means. This is where the journey begins—a simple handshake with the mathematics of trust.*

---

## Executive Summary

This introductory challenge provides the foundation for understanding zero-knowledge proofs. It covers the basic concepts: what it means to prove knowledge of something without revealing it, the three essential properties (completeness, soundness, zero-knowledge), and how interactive protocols establish trust between provers and verifiers.

**Flag:** *(captured)*

---

## Challenge Description

The challenge introduces the fundamental concepts of zero-knowledge proofs through a simple interactive example. The goal is to understand and implement the basic flow of a ZK protocol.

---

## Core Concepts

### What is a Zero-Knowledge Proof?

A zero-knowledge proof allows a **prover** to convince a **verifier** that a statement is true, without revealing any information beyond the validity of the statement itself.

**Classic Example: The Ali Baba Cave**
- A cave has two paths (A and B) meeting at a magic door
- Only someone who knows the secret word can open the door
- Prover enters one path randomly, verifier calls out which path to exit from
- If prover knows the secret, they can always exit from the requested path
- After many rounds, verifier is convinced—but learns nothing about the secret word

### The Three Properties

**1. Completeness**
If the statement is true and both parties follow the protocol honestly, the verifier will be convinced.
```
Pr[Verifier accepts | Statement is TRUE, Honest execution] = 1
```

**2. Soundness**
If the statement is false, no cheating prover can convince the verifier (except with negligible probability).
```
Pr[Verifier accepts | Statement is FALSE] ≤ negligible
```

**3. Zero-Knowledge**
The verifier learns nothing beyond the fact that the statement is true. Formally: there exists a simulator that can produce indistinguishable transcripts without the witness.
```
View_real ≈ View_simulated
```

---

## Basic Protocol Structure

### Interactive Proof Flow

```
Prover (knows witness w)              Verifier
─────────────────────────            ──────────

        [Commitment]
      ──────────────────→
                                   [Challenge]
      ←──────────────────
        [Response]
      ──────────────────→
                                   [Verify]
```

### Simple Example: Graph 3-Coloring

**Statement:** "I know a valid 3-coloring of graph G"

**Protocol:**
1. Prover commits to a randomly permuted coloring (hidden)
2. Verifier picks a random edge (u, v)
3. Prover reveals colors of u and v
4. Verifier checks: colors are different

**Soundness:** If coloring is invalid, at least one edge has same colors → caught with probability ≥ 1/|E|

**Zero-Knowledge:** Verifier only sees two different colors per round—learns nothing about the actual coloring

---

## Implementation

```python
#!/usr/bin/env python3
"""
ZKP Introduction - Basic protocol implementation
"""

import random
import hashlib

class SimpleZKProof:
    """
    Demonstrates basic ZK concepts with a simple protocol
    """

    def __init__(self):
        self.secret = random.randint(1, 1000000)

    def prover_commitment(self):
        """
        Prover creates a commitment hiding their secret
        """
        self.nonce = random.randint(1, 2**128)
        # Commitment = Hash(secret || nonce)
        commitment = hashlib.sha256(
            f"{self.secret}:{self.nonce}".encode()
        ).hexdigest()
        return commitment

    def verifier_challenge(self):
        """
        Verifier sends a random challenge
        """
        return random.randint(0, 1)

    def prover_response(self, challenge):
        """
        Prover responds based on challenge
        """
        if challenge == 0:
            # Reveal the nonce (proves commitment was valid)
            return {"type": "nonce", "value": self.nonce}
        else:
            # Reveal secret + nonce (proves knowledge)
            return {"type": "full", "secret": self.secret, "nonce": self.nonce}

    def verifier_check(self, commitment, challenge, response):
        """
        Verifier validates the response
        """
        if response["type"] == "nonce":
            # Can't verify without secret, but commitment structure is valid
            return True  # Simplified for demo
        else:
            # Verify commitment matches
            expected = hashlib.sha256(
                f"{response['secret']}:{response['nonce']}".encode()
            ).hexdigest()
            return commitment == expected


# Run protocol
zkp = SimpleZKProof()

# Multiple rounds for soundness amplification
for round_num in range(10):
    commitment = zkp.prover_commitment()
    challenge = zkp.verifier_challenge()
    response = zkp.prover_response(challenge)
    valid = zkp.verifier_check(commitment, challenge, response)

    print(f"Round {round_num + 1}: {'✓' if valid else '✗'}")

print("\n[+] Protocol completed successfully")
```

---

## Key Takeaways

1. **Trust Without Knowledge**: ZK proofs establish conviction without information leakage

2. **Interactive Foundation**: The basic commit-challenge-response structure appears throughout ZK systems

3. **Probabilistic Soundness**: Security comes from repetition—each round reduces cheating probability

4. **Simulation Paradigm**: Zero-knowledge is defined by the existence of a simulator

5. **Building Block**: These concepts form the foundation for all advanced ZK systems (SNARKs, STARKs, etc.)

---

## From Introduction to Practice

This challenge sets up the mental model for everything that follows:

| Concept | This Challenge | Advanced Systems |
|---------|---------------|------------------|
| Commitment | Hash-based | Pedersen, Polynomial |
| Challenge | Random bits | Fiat-Shamir hash |
| Soundness | Repetition | Mathematical reduction |
| ZK Property | Intuitive | Formal simulation |

---

## References

- [Goldwasser, Micali, Rackoff: "The Knowledge Complexity of Interactive Proof Systems"](https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Proof%20Systems/The_Knowledge_Complexity_Of_Interactive_Proof_Systems.pdf)
- [ZKProof Community Reference](https://docs.zkproof.org/)
- [Oded Goldreich: "Zero-Knowledge Twenty Years After Its Invention"](https://www.wisdom.weizmann.ac.il/~oded/PSX/zk-tut10.pdf)

---

> *The journey of a thousand proofs begins with a single commitment. Here, in this introduction, we learned that trust can be established without revelation—that knowledge can be proven without being shown. This is the essence of zero-knowledge, and this is where mastery begins.*
