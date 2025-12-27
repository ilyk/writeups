# Modular Arithmetic 1 (5 pts)

**Category:** Mathematics — Modular Math
**Difficulty:** Easy

---

## Challenge

Find the smallest positive integer equivalent to a large number modulo a prime.

---

## Vulnerability

Modular arithmetic is the foundation of public-key cryptography. All operations in RSA, ECC, and discrete log systems happen modulo some number.

**Key insight:** `a mod n` gives the remainder when a is divided by n, always in range [0, n-1].

---

## Solution

```python
# Find smallest positive integer equivalent to 11 mod 6
result1 = 11 % 6  # = 5

# For the challenge
a = 8146798528947
n = 17

result = a % n
print(result)
```

---

## Key Takeaway

**Modular reduction keeps numbers manageable.** In RSA with 2048-bit keys:
- Without reduction: exponentiation produces astronomically large numbers
- With reduction: all intermediate values stay under n

This is why modular exponentiation (square-and-multiply) is efficient despite huge exponents.

