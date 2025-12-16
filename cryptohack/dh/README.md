# Diffie-Hellman Challenges

**Platform:** CryptoHack
**Category:** Diffie-Hellman

Writeups for CryptoHack Diffie-Hellman challenges covering key exchange vulnerabilities, group theory attacks, and matrix-based cryptography.

---

## Challenges

### Starter (5 challenges)
| # | Challenge | Points | Technique |
|---|-----------|--------|-----------|
| 01 | [Working with Fields](01-working-with-fields.md) | 10 | Modular inverse |
| 02 | [Generators of Groups](02-generators-of-groups.md) | 20 | Group generators |
| 03 | [Computing Public Values](03-computing-public-values.md) | 25 | Modular exponentiation |
| 04 | [Computing Shared Secrets](04-computing-shared-secrets.md) | 30 | DH shared secret |
| 05 | [Deriving Symmetric Keys](05-deriving-symmetric-keys.md) | 40 | Key derivation |

### Man In The Middle (2 challenges)
| # | Challenge | Points | Technique |
|---|-----------|--------|-----------|
| 06 | [Parameter Injection](06-parameter-injection.md) | 60 | MITM parameter replacement |
| 07 | [Export-grade](07-export-grade.md) | 100 | Weak prime downgrade |

### Group Theory (3 challenges)
| # | Challenge | Points | Technique |
|---|-----------|--------|-----------|
| 08 | [Additive](08-additive.md) | 70 | Additive vs multiplicative |
| 09 | [Static Client](09-static-client.md) | 100 | Static key reuse |
| 10 | [Static Client 2](10-static-client-2.md) | 120 | Pohlig-Hellman |

### Miscellaneous (1 challenge)
| # | Challenge | Points | Technique |
|---|-----------|--------|-----------|
| 11 | [Script Kiddie](11-script-kiddie.md) | 70 | XOR vs exponentiation |

### Matrix Trilogy (3 challenges)
| # | Challenge | Points | Technique |
|---|-----------|--------|-----------|
| 12 | [The Matrix](12-the-matrix.md) | 75 | Matrix DLP over GF(2) |
| 13 | [The Matrix Reloaded](13-the-matrix-reloaded.md) | 100 | Jordan normal form |
| 14 | [The Matrix Revolutions](14-the-matrix-revolutions.md) | 125 | Matrix key derivation |

---

## Tools & Dependencies

- **Python:** pycryptodome, galois, sympy, pwntools
- **SageMath:** Required for Matrix Reloaded (Jordan form)

---

**Total: 14 challenges, 945 points**
