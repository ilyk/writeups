# Extended GCD (15 pts)

**Category:** Mathematics — Modular Math
**Difficulty:** Easy

---

## Challenge

Use the Extended Euclidean Algorithm to find Bézout coefficients.

---

## Vulnerability

The Extended GCD finds integers u, v such that `a*u + b*v = gcd(a, b)`. When gcd(a, n) = 1, this gives us the modular inverse.

**Key insight:** If `a*u + n*v = 1`, then `a*u ≡ 1 (mod n)`, so u is the modular inverse of a.

---

## Solution

```python
def extended_gcd(a, b):
    """Returns (gcd, u, v) where a*u + b*v = gcd"""
    if b == 0:
        return a, 1, 0
    gcd, u1, v1 = extended_gcd(b, a % b)
    return gcd, v1, u1 - (a // b) * v1

p = 26513
q = 32321

gcd, u, v = extended_gcd(p, q)
print(f"gcd = {gcd}")
print(f"u = {u}, v = {v}")
print(f"Verification: {p}*{u} + {q}*{v} = {p*u + q*v}")
```

---

## Key Takeaway

**Extended GCD computes modular inverses.** This is essential for:
- Computing RSA private keys: `d = e^(-1) mod φ(n)`
- Solving linear congruences
- Chinese Remainder Theorem applications
- Any situation requiring division in modular arithmetic

