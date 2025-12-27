# Manyprime (40 pts)

**Category:** RSA — Primes Part 1
**Difficulty:** Easy

---

## Challenge

An RSA modulus is the product of many small primes. Factor it.

---

## Vulnerability

Using many small primes instead of two large ones makes n easily factorable. Each small prime can be found with trial division or ECM.

**Key insight:** n composed of 32 primes of ~20 digits each is far weaker than n composed of 2 primes of ~300 digits each.

---

## Solution

```python
# Factor n using factordb.com or ECM
# Returns 32 small primes

primes = [p1, p2, ..., p32]  # All factors from factordb

# φ(n) = Π(p_i - 1) for all prime factors
phi = 1
for p in primes:
    phi *= (p - 1)

d = pow(e, -1, phi)
m = pow(ct, d, n)
```

---

## Key Takeaway

**Multi-prime RSA weakens security.** While multi-prime RSA (3+ primes) exists for performance, using many small primes is catastrophic:
- Each small prime is independently factorable
- ECM complexity scales with smallest factor size
- 32 × 20-digit primes << 2 × 300-digit primes in security

Standard RSA uses exactly 2 primes of equal size (half of n's bit length).

