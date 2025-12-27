# Unencryptable (125 pts)

**Category:** Mathematics — Brainteasers Part 2
**Difficulty:** Medium

---

## Challenge

RSA encryption where c = m^e mod N. The challenge hints at "fixed points" - messages that encrypt to themselves.

---

## Vulnerability

RSA fixed points are messages m where m^e ≡ m (mod N). These always include m ∈ {0, 1, N-1} and potentially others depending on the prime structure.

However, the actual vulnerability here is that N can be factored, enabling standard RSA decryption.

**Solution path:** Use FactorDB to factor N, then compute d = e^(-1) mod φ(N) and decrypt.

---

## Solution

```python
import requests
from Crypto.Util.number import long_to_bytes

N = ...  # from challenge
e = ...
c = ...

# Factor N using FactorDB API
resp = requests.get(f'http://factordb.com/api', params={'query': str(N)})
factors = resp.json()['factors']
p, q = int(factors[0][0]), int(factors[1][0])

# Standard RSA decryption
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, N)

flag = long_to_bytes(m)
print(flag.decode())
```

---

## Key Takeaway

**Always try to factor N first.** While the challenge name suggests a fixed-point attack, the simplest path is often direct factorization:

1. Check FactorDB for known factorizations
2. Try small factor checks (GCD with small primes)
3. Look for special N structures (p ≈ q, p = next_prime(q), etc.)

The flag ironically reminds us that fixed points are also secrets - the trivial fixed points {0, 1} reveal nothing, but non-trivial fixed points can leak information about the plaintext structure.
