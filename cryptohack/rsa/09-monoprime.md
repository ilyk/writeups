# Monoprime (30 pts)

**Category:** RSA — Primes Part 1
**Difficulty:** Easy

---

## Challenge

An RSA implementation uses only one prime instead of two. Break it.

---

## Vulnerability

Standard RSA uses n = p × q with φ(n) = (p-1)(q-1). When n is a single prime p, φ(n) = p - 1, making private key computation trivial.

**Key insight:** If n is prime, anyone can compute φ(n) = n - 1 and derive the private key.

---

## Solution

```python
def long_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

n = ...  # given prime
e = 65537
ct = ...

# n is prime, so φ(n) = n - 1
phi = n - 1
d = pow(e, -1, phi)

# Decrypt
m = pow(ct, d, n)
flag = long_to_bytes(m)
```

---

## Key Takeaway

**RSA requires composite moduli.** The security of RSA relies on:
- Difficulty of factoring n = p × q
- Impossibility of computing φ(n) without factors
- If n is prime, φ(n) is trivially n - 1

This is why RSA key generation always uses two (or more) distinct primes.

