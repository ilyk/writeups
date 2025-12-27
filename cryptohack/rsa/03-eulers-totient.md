# Euler's Totient (20 pts)

**Category:** RSA — Starter
**Difficulty:** Easy

---

## Challenge

Calculate Euler's totient φ(n) for RSA modulus n = p * q.

---

## Vulnerability

Euler's totient φ(n) counts integers from 1 to n that are coprime to n. For RSA, this is trivial if you know p and q: `φ(n) = (p-1)(q-1)`.

**Key insight:** Knowing φ(n) allows computing the private key d from the public exponent e. This is why factoring n breaks RSA.

---

## Solution

```python
p = 857504083339712752489993810777
q = 1029224947942998075080348647219

# For n = p * q where p, q are prime:
# φ(n) = (p-1)(q-1)
phi_n = (p - 1) * (q - 1)
print(phi_n)
```

---

## Key Takeaway

**φ(n) is the bridge from public to private key.** The relationship:
- Public key: (n, e)
- Private key: d = e^(-1) mod φ(n)

If an attacker can compute φ(n), they can compute d. For n = pq:
- Factoring n → φ(n) = (p-1)(q-1)
- φ(n) → can factor n (via quadratic equation)

These are computationally equivalent problems.

