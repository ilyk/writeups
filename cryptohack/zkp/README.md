# CryptoHack — Zero-Knowledge Proofs Writeups

**Platform:** [CryptoHack](https://cryptohack.org/)
**Category:** Zero-Knowledge Proofs
**Author:** ilyk
**Completion Date:** December 2025

---

## Overview

This directory contains detailed writeups for solved challenges from CryptoHack's Zero-Knowledge Proofs category. Each writeup follows a professional security research format, documenting the vulnerability exploited, exploitation methodology, root causes, and remediation strategies.

**Total Challenges Solved:** 5/8

---

## Challenges Completed

| # | Challenge | Points | Difficulty | Key Concept |
|---|-----------|--------|------------|-------------|
| 1 | [Pairing-Based Cryptography](01-pairing-based-cryptography.md) | 100 | Easy | Bilinear pairing misuse |
| 2 | [Mister Saplin's Preview](02-mister-saplins-preview.md) | 125 | Medium | SHVZK vs. malicious verifiers |
| 3 | [Couples](03-couples.md) | 150 | Medium-Hard | OR proof soundness |
| 4 | [Let's Prove It](04-lets-prove-it.md) | 150 | Medium-Hard | Verifier rewinding attacks |
| 5 | [Hamiltonicity](05-hamiltonicity.md) | 100 | Medium | Incomplete Fiat-Shamir hashing |

**Total Points Earned:** 625

---

## Key Learnings

### 1. **Pairing-Based Cryptography is Powerful but Dangerous**
Bilinear pairings can expose secrets if not properly randomized. The bilinearity property that makes them useful for advanced protocols also creates algebraic paths to witness extraction if mishandled.

### 2. **Special Honest-Verifier ZK ≠ Real-World Security**
SHVZK protocols assume honest verifiers—a fatal assumption against adversaries. Malicious verifiers can choose challenges to extract witnesses. **Lesson:** Always use protocols secure against malicious verifiers (or use Fiat-Shamir).

### 3. **OR Proofs Require Careful Challenge Management**
Composing Sigma protocols for disjunctive statements is subtle. Without proper commitment binding, both sub-proofs can be simulated, breaking soundness entirely. **Lesson:** Commitments must be fixed before challenges.

### 4. **Rewinding Attacks Exploit Determinism**
When provers reuse randomness or respond deterministically to repeated challenges, malicious verifiers can extract witnesses via the "special soundness" property. **Lesson:** Fresh, cryptographic randomness for every proof run.

### 5. **Hash the Entire Statement (Fiat-Shamir)**
Fiat-Shamir challenges must include the complete statement being proven. Omitting parts allows proof substitution attacks—proving about statement S₁ while claiming S₂. **Lesson:** `c = H(statement, commitment, params)` with no shortcuts.

---

## Common Vulnerability Patterns

### 1. Randomness Issues
- **Reused nonces** in Sigma protocols → Witness extraction
- **Weak PRNG** → Predictable challenges/responses
- **No fresh randomness** → Replay and rewinding attacks

### 2. Incomplete Hashing
- **Missing statement components** in Fiat-Shamir → Proof substitution
- **No domain separation** → Cross-protocol attacks
- **Omitted public parameters** → Context confusion

### 3. Weak Security Notions
- **SHVZK instead of Full ZK** → Malicious verifier attacks
- **Honest-verifier assumptions** → Real adversaries break the protocol
- **Interactive without protections** → Rewinding exploits

### 4. Protocol Composition Errors
- **OR proofs without binding** → Dual simulation
- **Missing commitment schemes** → Adaptive forgery
- **Improper challenge decomposition** → Soundness failure

---

## Exploitation Techniques Used

1. **Bilinear Pairing Exploitation**: Leveraging pairing properties to solve for secrets
2. **Malicious Challenge Selection**: Choosing non-uniform challenges to extract information
3. **Backward Commitment Construction**: Computing commitments after seeing challenges
4. **Verifier Rewinding**: Requesting multiple transcripts with same commitment
5. **Statement Substitution**: Proving about graph G' while claiming graph G
6. **Linear System Construction**: Building equations from multiple transcripts to solve for witnesses

---

## Defensive Principles

### Zero-Knowledge Proof Security Checklist

✅ **Use Proven Protocols**: Schnorr, Groth16, PLONK, STARKs—not ad-hoc designs
✅ **Fiat-Shamir Done Right**: `c = H(statement, all_public_inputs, commitment, domain_tag)`
✅ **Fresh Randomness**: Cryptographically secure, unique per proof
✅ **Commitment Binding**: Commitments fixed before challenges (hash commitment or non-interactive)
✅ **Full Security Proofs**: Prove ZK, soundness, completeness formally
✅ **Malicious Verifier Resistance**: Assume all verifiers are adversarial
✅ **Domain Separation**: Different protocols/contexts get different hash prefixes
✅ **No Rewinding Exploits**: Use non-interactive protocols or protect against transcript collection

---

## References & Resources

### Academic Papers
- [Fiat-Shamir Heuristic](https://link.springer.com/chapter/10.1007/3-540-47721-7_12)
- [On Σ-Protocols](https://www.win.tue.nl/~berry/CryptographicProtocols/LectureNotes.pdf)
- [Groth16 zk-SNARK](https://eprint.iacr.org/2016/260)
- [PLONK](https://eprint.iacr.org/2019/953)

### Educational Resources
- [ZK Proof Primer](https://zkp.science/)
- [Justin Thaler's ZK Book](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.html)
- [ZK Security Best Practices](https://eprint.iacr.org/2023/691)

### Tools & Libraries
- [libsnark](https://github.com/scipr-lab/libsnark)
- [bellman](https://github.com/zkcrypto/bellman)
- [circom](https://github.com/iden3/circom)
- [py_ecc (Ethereum)](https://github.com/ethereum/py_ecc)

---

## Challenges Not Yet Solved

The following challenges remain open:

- **Hamiltonicity 2** (175 pts) — Advanced Fiat-Shamir exploitation
- **Mister Saplins The Prover** (125 pts) — Unknown vulnerability
- **Let's Prove It Again** (175 pts) — Advanced verifier attacks

These represent advanced topics requiring deeper cryptographic analysis or novel attack vectors.

---

## Methodology

Each writeup follows this structure:

1. **Executive Summary**: High-level vulnerability description and impact
2. **Challenge Description**: Protocol and cryptographic setup
3. **Vulnerability Analysis**: Root cause and theoretical exploitation
4. **Exploitation**: Step-by-step attack implementation with code
5. **Root Causes**: Fundamental design/implementation flaws
6. **Remediation**: Immediate fixes and long-term security improvements
7. **Key Takeaways**: Lessons learned and broader implications
8. **References**: Academic papers and educational resources

---

## License & Usage

These writeups are provided for educational purposes. Code snippets are illustrative and should not be used in production systems. All flags have been redacted per standard responsible disclosure practices.

---

## Contact

For questions, corrections, or discussions about these writeups:
- GitHub: [@ilyk](https://github.com/ilyk)
- Repository: [ilyk/writeups](https://github.com/ilyk/writeups)

---

> *Zero-knowledge proofs are the poetry of cryptography—proving truth without revealing secrets. But poetry requires precision. A single misplaced word, one omitted verse, and the oracle speaks lies instead of riddles. These writeups document the moments when the incantations failed, and the secrets—meant to stay hidden—emerged into the light.*
