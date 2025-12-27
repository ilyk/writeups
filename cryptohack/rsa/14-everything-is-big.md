# Everything is Big (70 pts)

**Category:** RSA — Public Exponent
**Difficulty:** Medium

---

## Challenge

RSA with an unusually large public exponent. The name suggests something is "too big."

---

## Vulnerability

When e is very large, d must be correspondingly small (since e × d ≡ 1 mod φ(n)). Wiener's attack exploits small d using continued fraction expansion.

**Key insight:** The continued fraction expansion of e/n produces convergents, one of which equals k/d, revealing the private exponent.

---

## Solution

```python
def continued_fraction(a, b):
    """Generate continued fraction of a/b"""
    cf = []
    while b:
        cf.append(a // b)
        a, b = b, a % b
    return cf

def convergents(cf):
    """Generate convergents from continued fraction"""
    n0, n1 = cf[0], cf[0]*cf[1] + 1
    d0, d1 = 1, cf[1]
    yield n0, d0
    yield n1, d1
    for i in range(2, len(cf)):
        yield cf[i] * n1 + n0, cf[i] * d1 + d0
        n0, n1 = n1, cf[i] * n1 + n0
        d0, d1 = d1, cf[i] * d1 + d0

def wiener_attack(e, n):
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            # Verify by checking if n factors correctly
            # ... validation logic
            return d
    return None
```

---

## Key Takeaway

**Wiener's attack breaks RSA when d < n^0.25.** Protection requires:
- Using standard e = 65537 (ensures d is large)
- Avoiding custom exponent choices
- d should be approximately the same size as n

The attack uses O(log n) convergent checks, making it very efficient.

