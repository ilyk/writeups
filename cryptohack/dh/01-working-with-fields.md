# Working with Fields (10 pts)

**Category:** Diffie-Hellman — Starter
**Difficulty:** Easy

---

## Challenge

Introduction to finite field arithmetic. Compute the multiplicative inverse of an element in a prime field.

---

## Solution

In a prime field GF(p), the multiplicative inverse of `a` is the value `a⁻¹` such that:
```
a · a⁻¹ ≡ 1 (mod p)
```

Using Fermat's Little Theorem:
```
a^(p-1) ≡ 1 (mod p)
```

Therefore:
```
a⁻¹ ≡ a^(p-2) (mod p)
```

```python
def multiplicative_inverse(a, p):
    return pow(a, p - 2, p)

# Or using Python's built-in:
inverse = pow(a, -1, p)
```

---

## Key Takeaway

Modular inverses are fundamental to DH and most public-key cryptography. Python 3.8+ supports `pow(a, -1, p)` directly.
