# CryptoHack — Zero-Knowledge Proofs Writeups

**Platform:** [CryptoHack](https://cryptohack.org/)
**Category:** Zero-Knowledge Proofs
**Author:** ilyk
**Date:** December 2025

---

## Overview

Detailed writeups for 14 solved challenges from CryptoHack's Zero-Knowledge Proofs category. Each writeup documents the vulnerability exploited, exploitation methodology, and remediation strategies.

**Challenges Solved:** 14
**Challenges Remaining:** 4 (Hamiltonicity 2, Mister Saplins The Prover, Let's Prove It Again, Couples)

---

## Challenges

| # | Challenge | Points | Writeup |
|---|-----------|--------|---------|
| 1 | ZKP Introduction | 5 | [01-zkp-introduction.md](01-zkp-introduction.md) |
| 2 | Proofs of Knowledge | 20 | [02-proofs-of-knowledge.md](02-proofs-of-knowledge.md) |
| 3 | Special Soundness | 25 | [03-special-soundness.md](03-special-soundness.md) |
| 4 | Honest Verifier Zero Knowledge | 30 | [04-hvzk.md](04-hvzk.md) |
| 5 | Non-Interactive | 35 | [05-non-interactive.md](05-non-interactive.md) |
| 6 | Pairing-Based Cryptography | 50 | [06-pairing-based-cryptography.md](06-pairing-based-cryptography.md) |
| 7 | Too Honest | 50 | [07-too-honest.md](07-too-honest.md) |
| 8 | OR Proof | 75 | [08-or-proof.md](08-or-proof.md) |
| 9 | Mister Saplin's Preview | 80 | [09-mister-saplins-preview.md](09-mister-saplins-preview.md) |
| 10 | Hamiltonicity | 100 | [10-hamiltonicity.md](10-hamiltonicity.md) |
| 11 | Couples | 100 | [11-couples.md](11-couples.md) |
| 12 | Let's Prove It | 120 | [12-lets-prove-it.md](12-lets-prove-it.md) |
| 13 | Fischlin Transform | 180 | [13-fischlin-transform.md](13-fischlin-transform.md) |
| 14 | Ticket Maestro | 200 | [14-ticket-maestro.md](14-ticket-maestro.md) |

---

## Key Concepts Covered

### Sigma Protocols
- Basic three-move structure (Commit-Challenge-Response)
- Special soundness and witness extraction
- Honest-verifier zero-knowledge (HVZK)
- Fiat-Shamir transformation to NIZK

### Attack Techniques
- Randomness reuse exploitation
- Verifier rewinding attacks
- Incomplete Fiat-Shamir hashing
- Edge case exploitation
- OR proof soundness attacks

### Advanced Topics
- Fischlin transform (online extraction)
- Pairing-based cryptography misuse
- Protocol composition vulnerabilities
- Ticket/credential systems

---

## Vulnerability Patterns

1. **Randomness Reuse** — Reusing nonces enables witness extraction via special soundness
2. **Incomplete Hashing** — Fiat-Shamir challenges must include the full statement
3. **SHVZK Limitations** — Honest-verifier assumptions fail against malicious verifiers
4. **Edge Cases** — Unused parameters and boundary conditions create attack surfaces
5. **Composition Flaws** — Combining secure protocols doesn't guarantee security

---

## References

- [Damgård: On Σ-Protocols](https://www.cs.au.dk/~ivan/Sigma.pdf)
- [Fiat-Shamir Heuristic](https://link.springer.com/chapter/10.1007/3-540-47721-7_12)
- [Fischlin Transform](https://eprint.iacr.org/2005/089)
- [ZKProof Community](https://zkproof.org/)

---

> *Zero-knowledge proofs are elegant mathematics—until implementation introduces the human element. These writeups document where theory met reality, and reality lost.*
