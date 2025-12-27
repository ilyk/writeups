# Fast Primes (75 pts)

**Category:** RSA — Primes Part 2
**Difficulty:** Medium

---

## Challenge

A "fast" prime generation method that produces primes of the form p = k × M + e^a mod M, where M is the primorial of the first 40 primes and k is a small multiplier.

---

## Vulnerability

This prime generation scheme resembles the ROCA vulnerability (CVE-2017-15361) that affected Infineon chips. The special structure means:
- p mod M = e^a mod M is predictable
- The search space for k is small (2^28 to 2^29)
- The modulus has exploitable algebraic structure

**Key insight:** The primorial structure severely constrains the prime, making it factorable through specialized algorithms or lookup in factorization databases.

---

## Solution

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# The small modulus size (512 bits) and special structure
# means factordb.com often has the factorization

# For larger keys, the attack involves:
# 1. Compute discrete log of n mod M to find a_p + a_q
# 2. Enumerate possible (a_p, a_q) pairs
# 3. For each pair, search k values to find factors

# In practice for this challenge:
p = ...  # from factordb
q = n // p

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

key = RSA.construct((n, e, d))
cipher = PKCS1_OAEP.new(key)
plaintext = cipher.decrypt(ciphertext)
```

---

## Key Takeaway

**Structured prime generation is dangerous.** The ROCA vulnerability affected millions of Estonian ID cards and other cryptographic devices. Key lessons:
- Random primes must come from cryptographically secure RNGs
- "Fast" generation often trades security for speed
- Algebraic structure in primes enables specialized factorization
- Even subtle patterns can be exploited

The flag references "Poor Estonia," highlighting the real-world impact of this vulnerability class.

