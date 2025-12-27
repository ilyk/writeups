# Private Keys (20 pts)

**Category:** RSA — Starter
**Difficulty:** Easy

---

## Challenge

Calculate the RSA private exponent d from p, q, and e.

---

## Vulnerability

The private exponent d is the modular inverse of e modulo φ(n). Knowing p and q makes this trivial.

**Key insight:** `d = e^(-1) mod φ(n)` where `φ(n) = (p-1)(q-1)`.

---

## Solution

```python
p = 857504083339712752489993810777
q = 1029224947942998075080348647219
e = 65537

# Calculate Euler's totient
phi_n = (p - 1) * (q - 1)

# Private exponent is modular inverse of e
d = pow(e, -1, phi_n)  # Python 3.8+
print(d)
```

---

## Key Takeaway

**The private key is just a modular inverse.** Given the factorization of n:
1. Compute φ(n) = (p-1)(q-1)
2. Compute d = e^(-1) mod φ(n)
3. Decryption: m = c^d mod n

This is why RSA's security relies entirely on the difficulty of factoring n. Any factorization method (ECM, GNFS, quantum Shor's algorithm) breaks RSA.

