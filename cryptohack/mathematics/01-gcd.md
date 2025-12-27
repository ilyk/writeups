# Greatest Common Divisor (5 pts)

**Category:** Mathematics — Modular Math
**Difficulty:** Easy

---

## Challenge

Calculate the GCD of two large integers.

---

## Vulnerability

The Euclidean algorithm efficiently computes GCD in O(log min(a,b)) steps. This is fundamental to RSA key generation and attacks.

**Key insight:** GCD(a, b) = GCD(b, a mod b), recursively until b = 0.

---

## Solution

```python
import math

a = 66528
b = 52920

# Python's built-in GCD
result = math.gcd(a, b)
print(result)
```

---

## Key Takeaway

**GCD is cryptographically critical.** It's used in:
- RSA key generation (p and q must be coprime to e)
- Detecting weak RSA keys (shared factors between moduli)
- Extended Euclidean Algorithm (computing modular inverses)
- Pollard's rho and other factoring algorithms

