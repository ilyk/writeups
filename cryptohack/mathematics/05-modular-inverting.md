# Modular Inverting (10 pts)

**Category:** Mathematics — Modular Math
**Difficulty:** Easy

---

## Challenge

Find the modular inverse of a number modulo a prime.

---

## Vulnerability

The modular inverse of a modulo n is a number b such that `a * b ≡ 1 (mod n)`. It exists only when gcd(a, n) = 1.

**Key insight:** For prime p, we can use Fermat's Little Theorem: `a^(-1) ≡ a^(p-2) (mod p)`.

---

## Solution

```python
# Find d such that 3 * d ≡ 1 (mod 13)
a = 3
p = 13

# Method 1: Extended Euclidean Algorithm
def modinv(a, n):
    def egcd(a, b):
        if b == 0:
            return a, 1, 0
        g, x, y = egcd(b, a % b)
        return g, y, x - (a // b) * y
    g, x, _ = egcd(a % n, n)
    return x % n

# Method 2: Fermat's Little Theorem (for prime modulus)
d = pow(a, p - 2, p)
print(d)

# Verify: 3 * d mod 13 = 1
print(f"Verification: {a} * {d} mod {p} = {(a * d) % p}")
```

---

## Key Takeaway

**Modular inverse is "division" in modular arithmetic.** Computing `a/b mod n` means `a * b^(-1) mod n`. Critical for:
- RSA private key: `d = e^(-1) mod φ(n)`
- Solving linear congruences
- Elliptic curve point operations
- Any algorithm requiring modular division

Python 3.8+ provides `pow(a, -1, n)` for direct computation.

