# Modular Exponentiation (10 pts)

**Category:** RSA — Starter
**Difficulty:** Easy

---

## Challenge

Compute a modular exponentiation: `101^17 mod 22663`.

---

## Vulnerability

Modular exponentiation is the core operation in RSA encryption and decryption. Naive exponentiation followed by modular reduction is impractical for large numbers.

**Key insight:** Square-and-multiply algorithm computes `a^e mod n` efficiently by processing exponent bits and reducing at each step.

---

## Solution

```python
base = 101
exponent = 17
modulus = 22663

# Python's built-in pow() handles this efficiently
result = pow(base, exponent, modulus)
print(result)
```

---

## Key Takeaway

**Use `pow(base, exp, mod)` for modular exponentiation.** Never do `(base ** exp) % mod` for large numbers—it computes the full power first, which is astronomically large for RSA-sized exponents.

The three-argument `pow()` uses binary exponentiation with modular reduction at each step, keeping intermediate values manageable.

