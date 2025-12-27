# Ron was Wrong, Whit is Right (90 pts)

**Category:** RSA — Primes Part 2
**Difficulty:** Medium

---

## Challenge

A collection of 50 RSA public keys and their corresponding PKCS#1 OAEP encrypted messages. The challenge references a famous 2012 research paper.

---

## Vulnerability

When RSA keys are generated with weak random number generators, different keys may share prime factors. The batch GCD algorithm efficiently finds shared factors across millions of keys in near-linear time.

**Key insight:** If two moduli n₁ = p × q₁ and n₂ = p × q₂ share a prime p, then gcd(n₁, n₂) = p, instantly factoring both.

---

## Solution

```python
from functools import reduce
from math import gcd

def batch_gcd(moduli):
    """Efficient batch GCD using product tree."""
    # Build product tree
    tree = [moduli]
    while len(tree[-1]) > 1:
        level = []
        for i in range(0, len(tree[-1]), 2):
            if i + 1 < len(tree[-1]):
                level.append(tree[-1][i] * tree[-1][i+1])
            else:
                level.append(tree[-1][i])
        tree.append(level)

    # Compute remainders
    product = tree[-1][0]
    remainders = [product]
    for level in reversed(tree[:-1]):
        new_remainders = []
        for i, val in enumerate(level):
            new_remainders.append(remainders[i // 2] % (val * val))
        remainders = new_remainders

    # Extract GCDs
    return [gcd(r // n, n) for r, n in zip(remainders, moduli)]

# Find keys with shared factors
gcds = batch_gcd([key.n for key in keys])
for i, g in enumerate(gcds):
    if g != 1 and g != keys[i].n:
        p = g
        q = keys[i].n // p
        # Decrypt message i
```

---

## Key Takeaway

**Weak RNG in key generation is catastrophic.** The 2012 paper "Ron was Wrong, Whit is Right" found that 0.2% of HTTPS keys shared factors due to poor entropy during generation. Lessons:
- Key generation requires high-quality randomness
- Embedded devices and VMs are particularly vulnerable
- Batch GCD can audit millions of keys efficiently
- A single shared factor compromises both keys completely

The flag references Euclid, inventor of the GCD algorithm.

