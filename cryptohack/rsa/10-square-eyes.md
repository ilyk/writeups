# Square Eyes (35 pts)

**Category:** RSA — Primes Part 1
**Difficulty:** Easy

---

## Challenge

An RSA modulus seems unusually structured. Find the weakness.

---

## Vulnerability

When n = p², computing the square root of n reveals p directly. For n = p², φ(n) = p² - p = p(p-1).

**Key insight:** Perfect square detection and integer square root computation are both O(log n), making this trivially breakable.

---

## Solution

```python
from math import isqrt

def long_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

n = ...  # given
e = 65537
ct = ...

# n = p², so take square root
p = isqrt(n)
assert p * p == n  # Verify it's a perfect square

# φ(p²) = p² - p = p(p-1)
phi = p * (p - 1)
d = pow(e, -1, phi)

m = pow(ct, d, n)
flag = long_to_bytes(m)
```

---

## Key Takeaway

**RSA requires distinct prime factors.** Using n = p²:
- Square root reveals p in O(log n) time
- Euler's totient is easily computed: φ(p^k) = p^(k-1)(p-1)
- Same vulnerability applies to n = p^k for any k > 1

Always use n = p × q where p ≠ q and both are large, random primes.

