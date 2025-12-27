# Crossed Wires (100 pts)

**Category:** RSA — Public Exponent
**Difficulty:** Medium

---

## Challenge

A user encrypts a message for multiple friends, but makes a critical mistake—using their own private key parameters during encryption instead of properly using their friends' public keys.

---

## Vulnerability

The challenge provides the user's private key (N, d) and the friends' public keys (all sharing the same N but with different small exponents). The message is encrypted sequentially through all friend keys.

**Key insight:** With d and e = 0x10001, we can factor N using the relation e × d - 1 = k × φ(N). Then we compute a combined decryption exponent for the chained encryption.

---

## Solution

```python
import random
from math import gcd

def factor_with_private_key(n, e, d):
    """Factor n given e and d using probabilistic method."""
    k = e * d - 1
    while True:
        g = random.randint(2, n - 2)
        t = k
        while t % 2 == 0:
            t //= 2
            x = pow(g, t, n)
            if x > 1 and gcd(x - 1, n) > 1:
                p = gcd(x - 1, n)
                if p != n:
                    return p, n // p

# Factor N using the private key
p, q = factor_with_private_key(N, 0x10001, d)
phi = (p - 1) * (q - 1)

# Combine all friend exponents
combined_e = e1 * e2 * e3 * e4 * e5
combined_d = pow(combined_e, -1, phi)

# Decrypt
m = pow(ciphertext, combined_d, N)
```

---

## Key Takeaway

**Having a private key allows factoring the modulus.** The relationship e × d ≡ 1 (mod φ(N)) leaks enough information to factor N probabilistically. This demonstrates why:
- Private keys must never be exposed
- Shared moduli across users are catastrophic
- Key material must be protected at rest and in transit

