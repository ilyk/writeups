# Factoring (15 pts)

**Category:** RSA — Primes Part 1
**Difficulty:** Easy

---

## Challenge

Factor a small RSA modulus to find the prime factors.

---

## Vulnerability

Small RSA moduli can be factored by trial division, Fermat's method, or online databases like factordb.com.

**Key insight:** Real RSA security requires n to be at least 2048 bits. Smaller moduli can be factored with modern algorithms.

---

## Solution

```python
from sympy import factorint

n = 510143758735509025530880200653196460532653147

# For small numbers, sympy can factor directly
factors = factorint(n)
print(factors)

# Or use online factordb.com for known factorizations
# Result: n = p * q
p = min(factors.keys())
print(p)
```

Alternative using trial division for very small factors:
```python
def factor(n):
    """Simple trial division"""
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return i, n // i
    return n, 1

p, q = factor(n)
print(f"p = {p}")
print(f"q = {q}")
```

---

## Key Takeaway

**Factoring difficulty is RSA's foundation.** For a 2048-bit RSA modulus:
- Trial division: infeasible (would take longer than universe age)
- General Number Field Sieve: still infeasible with current computing
- Quantum computers (Shor's algorithm): would break RSA, not yet practical

Always check factordb.com first—many CTF challenges use previously-factored or weak moduli.

