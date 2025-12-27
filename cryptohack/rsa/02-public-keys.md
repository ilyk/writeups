# Public Keys (15 pts)

**Category:** RSA — Starter
**Difficulty:** Easy

---

## Challenge

Given two primes p=17 and q=23, encrypt the message m=12 using public exponent e=65537.

---

## Vulnerability

RSA encryption is straightforward: `c = m^e mod n` where n = p*q. The security relies on the difficulty of factoring n to recover p and q.

**Key insight:** With small primes, RSA provides no security—n can be trivially factored. Real RSA uses 2048+ bit primes.

---

## Solution

```python
p = 17
q = 23
e = 65537
m = 12

# Compute public modulus
n = p * q  # 391

# Encrypt: c = m^e mod n
c = pow(m, e, n)
print(c)
```

---

## Key Takeaway

**RSA encryption is just modular exponentiation.** The public key (n, e) is all that's needed to encrypt. Security comes from:
- Large n (2048+ bits) making factorization infeasible
- Proper padding (OAEP) preventing various attacks
- e chosen to avoid weak-exponent attacks (65537 is standard)

