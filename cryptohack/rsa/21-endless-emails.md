# Endless Emails (150 pts)

**Category:** RSA — Public Exponent
**Difficulty:** Hard

---

## Challenge

Professor Johan Håstad is answering student emails. Multiple students receive RSA-encrypted responses using e = 3 but different moduli. The challenge provides several ciphertexts and their corresponding public keys.

---

## Vulnerability

This is the classic Håstad broadcast attack. When the same message is encrypted with a small exponent e to e or more recipients with coprime moduli, the Chinese Remainder Theorem allows recovery of m^e, from which m can be computed via integer e-th root.

**Key insight:** Not all messages are identical—the challenge requires identifying which subset of ciphertexts encrypt the same message. The name references Johan Håstad, who proved this attack.

---

## Solution

```python
from itertools import combinations
from functools import reduce
import gmpy2

def crt(remainders, moduli):
    """Chinese Remainder Theorem."""
    N = reduce(lambda a, b: a * b, moduli)
    result = 0
    for ri, mi in zip(remainders, moduli):
        Ni = N // mi
        inv = pow(Ni, -1, mi)
        result = (result + ri * Ni * inv) % N
    return result

# Try all combinations of 3 ciphertexts (for e=3)
for indices in combinations(range(len(data)), 3):
    ns = [data[i][0] for i in indices]
    cs = [data[i][1] for i in indices]

    m_cubed = crt(cs, ns)
    m, exact = gmpy2.iroot(m_cubed, 3)

    if exact:
        flag = long_to_bytes(int(m))
        print(f"Found: {flag}")
        break
```

---

## Key Takeaway

**Small public exponents enable broadcast attacks.** When e = 3 and the same message goes to 3+ recipients:
- CRT combines ciphertexts: m³ mod (n₁×n₂×n₃)
- Since m < n_i, we have m³ < n₁×n₂×n₃
- Simple integer cube root recovers m

Protection requires randomized padding (OAEP) to ensure each encryption produces a unique ciphertext, even for identical plaintexts.

