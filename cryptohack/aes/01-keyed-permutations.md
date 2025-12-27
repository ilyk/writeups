# Keyed Permutations (5 pts)

**Category:** AES — How AES Works
**Difficulty:** Easy

---

## Challenge

Identify the mathematical term for a one-to-one function mapping a set to itself.

---

## Vulnerability

Understanding the mathematical foundations of AES is crucial for cryptanalysis. AES's S-box must be a bijection (one-to-one and onto) to be reversible.

**Key insight:** A bijection ensures every input maps to a unique output, and vice versa—required for decryption to work.

---

## Solution

The answer is simply knowing the terminology:
- **Bijection** - a function that is both injective (one-to-one) and surjective (onto)

In AES context:
- The S-box is a bijection: each of 256 inputs maps to exactly one of 256 outputs
- No two inputs produce the same output
- Every output is reachable from exactly one input

---

## Key Takeaway

**Bijections enable reversibility.** In block ciphers:
- S-boxes must be bijections for decryption
- The entire cipher is a keyed bijection (permutation) on the block space
- AES permutes the space of 128-bit blocks based on the key

