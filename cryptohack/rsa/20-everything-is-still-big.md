# Everything is Still Big (100 pts)

**Category:** RSA — Public Exponent
**Difficulty:** Medium

---

## Challenge

Another RSA instance with an unusually large public exponent e. The private exponent d is generated as a 512-bit random number, with a check ensuring (3×d)⁴ > N.

---

## Vulnerability

Despite the check attempting to prevent Wiener's attack, the private exponent d remains small enough to be vulnerable. The bound (3×d)⁴ > N ensures d > N^0.25/3, but Wiener's attack works for d < N^0.25/3.

**Key insight:** The 512-bit d against a 2048-bit N means d ≈ N^0.25, right at the theoretical boundary. In practice, Wiener's continued fraction method often succeeds even at this edge case.

---

## Solution

```python
def continued_fraction(num, denom):
    while denom:
        q = num // denom
        yield q
        num, denom = denom, num - q * denom

def convergents(cf):
    n0, d0 = 0, 1
    n1, d1 = 1, 0
    for q in cf:
        n2 = q * n1 + n0
        d2 = q * d1 + d0
        yield n2, d2
        n0, d0 = n1, d1
        n1, d1 = n2, d2

def wiener_attack(e, n):
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Verify: check if n factors correctly
        s = n - phi + 1
        discriminant = s * s - 4 * n
        if discriminant >= 0:
            sqrt_d = isqrt(discriminant)
            if sqrt_d * sqrt_d == discriminant:
                return d
    return None

d = wiener_attack(e, n)
m = pow(c, d, n)
```

---

## Key Takeaway

**Wiener's attack boundary is sharp but not absolute.** Even when d is at the theoretical limit of N^0.25, the attack may succeed. The title's reference to "Boneh's attack" hints at the stronger Boneh-Durfee bound (d < N^0.292), but standard Wiener suffices here.

Protection requires d to be significantly larger than N^0.25—using standard e = 65537 naturally ensures this.

