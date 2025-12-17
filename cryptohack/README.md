# CryptoHack Writeups

**Platform:** [CryptoHack](https://cryptohack.org/)
**Author:** ilyk
**Date:** December 2025

---

## Overview

Writeups for CryptoHack challenges covering cryptography, hash functions, web security, and zero-knowledge proofs.

**Total Challenges:** 56 (54 solved)

---

## Categories

| Category | Challenges | Points | Status |
|----------|------------|--------|--------|
| [Diffie-Hellman](dh/) | 14 | 945 | Complete |
| [Hash Functions](hashes/) | 14 (12 solved) | 1065/1290 | 82.6% |
| [Web (JWT/TLS)](web/) | 14 | 850 | Complete |
| [Zero-Knowledge Proofs](zkp/) | 16 | 1270 | Complete |

---

## Challenge Breakdown

### Diffie-Hellman (14 challenges)
Key exchange vulnerabilities, group theory attacks, and matrix-based cryptography.
- Starter challenges (5)
- Man-in-the-Middle attacks (2)
- Group theory attacks (3)
- Matrix trilogy (3)
- Miscellaneous (1)

### Hash Functions (14 challenges, 12 solved)
Birthday attacks, MD5 collisions, length extension, preimage attacks, and hash-based signatures.
- Probability (2)
- Collisions (5, 4 solved)
- Length Extension (2, 1 solved)
- Pre-image (2)
- Hash-based Crypto (3)

### Web (14 challenges)
JWT token attacks and TLS protocol analysis.
- JSON Web Tokens (7)
- TLS/HTTPS (7)

### Zero-Knowledge Proofs (16 challenges)
Sigma protocols, Fiat-Shamir, and advanced ZKP attacks.
- Fundamentals (6)
- Attack techniques (5)
- Advanced protocols (5)

---

## Key Techniques

| Category | Techniques |
|----------|------------|
| DH | Pohlig-Hellman, MITM, Jordan form, smooth primes |
| Hashes | Birthday attack, MD5 collision, length extension, invariant subspace |
| Web | Algorithm confusion, key injection, TLS decryption |
| ZKP | Witness extraction, rewinding, Fischlin transform |

---

## Tools Used

- **Python:** pycryptodome, pwntools, sympy, galois, hashpumpy
- **SageMath:** Matrix operations, Jordan form
- **Wireshark/tshark:** TLS packet analysis
- **Hash tools:** fastcoll, HashClash (MD5 collision generation)
