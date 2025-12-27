# Modular Arithmetic 2 (10 pts)

**Category:** Mathematics — Modular Math
**Difficulty:** Easy

---

## Challenge

Apply Fermat's Little Theorem to compute a modular exponentiation.

---

## Vulnerability

Fermat's Little Theorem states: if p is prime and gcd(a, p) = 1, then `a^(p-1) ≡ 1 (mod p)`.

**Key insight:** This means `a^(p-1) mod p = 1`, which is the basis for RSA's correctness and efficient computation.

---

## Solution

```python
# Fermat's Little Theorem: a^(p-1) ≡ 1 (mod p) for prime p
p = 65537  # A prime number (commonly used as RSA public exponent)

# For any a coprime to p:
# a^(p-1) mod p = 1

# The challenge asks for 273246787654^(65536) mod 65537
# Note: 65536 = 65537 - 1 = p - 1
# So by Fermat's Little Theorem, the answer is 1

print(pow(273246787654, 65536, 65537))
```

---

## Key Takeaway

**Fermat's Little Theorem enables RSA.** It guarantees that:
- For message m: `m^(e*d) ≡ m (mod n)` when e*d ≡ 1 (mod φ(n))
- Decryption reverses encryption
- The private key correctly inverts the public key

Euler's generalization (φ(n) for composite n) extends this to RSA's composite modulus.

