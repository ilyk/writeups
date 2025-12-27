# Inferius Prime (30 pts)

**Category:** RSA — Primes Part 1
**Difficulty:** Easy

---

## Challenge

A "super-strong" RSA implementation claims 1600-bit security. Find the flaw.

---

## Vulnerability

The code uses `getPrime(100)` for both p and q, mistakenly believing this yields 1600-bit security. In reality, n = p × q is only ~200 bits.

**Key insight:** The author confused bits with bytes. 100-bit primes create a 200-bit modulus, trivially factorable by any modern factoring tool.

---

## Solution

```python
from sympy import factorint

n = 984994081290620368062168960884976209711107645166770780785733
e = 65537
ct = 948553474947320504624302879933619818331484350431616834086273

# n is only ~200 bits - factor it easily
# Use factordb.com or sympy
factors = factorint(n)
p, q = list(factors.keys())

# Standard RSA decryption
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(ct, d, n)
```

---

## Key Takeaway

**RSA security depends on n's bit length, not p and q individually.** For secure RSA:
- 2048-bit n minimum (two 1024-bit primes)
- 4096-bit n for long-term security
- Always verify key sizes match security requirements

