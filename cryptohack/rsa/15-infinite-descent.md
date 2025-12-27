# Infinite Descent (50 pts)

**Category:** RSA — Primes Part 2
**Difficulty:** Medium

---

## Challenge

RSA with primes that are "close" to each other. The name references Fermat's method of infinite descent.

---

## Vulnerability

When p and q are close together, Fermat's factorization is extremely efficient. If p ≈ q, then n = p × q ≈ p², meaning √n ≈ p.

**Key insight:** Fermat's method expresses n as a² - b² = (a+b)(a-b). Starting from a = ⌈√n⌉ and incrementing, we quickly find a where a² - n is a perfect square.

---

## Solution

```python
from math import isqrt

def fermat_factor(n):
    """Fermat factorization for close primes"""
    a = isqrt(n)
    if a * a < n:
        a += 1
    while True:
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a + b, a - b
        a += 1

n = ...  # given
e = 65537
ct = ...

p, q = fermat_factor(n)
assert p * q == n

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(ct, d, n)
```

---

## Key Takeaway

**Primes must differ significantly.** Fermat's method finds factors in O(|p - q|) iterations. Protection requires:
- |p - q| > n^0.25 (at minimum)
- Random, independent prime generation
- Each prime should be roughly half of n's bit length

The attack is nearly instant when primes are within a few thousand of each other.

