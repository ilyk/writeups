# Bespoke Padding (100 pts)

**Category:** RSA — Padding
**Difficulty:** Medium

---

## Challenge

An RSA encryption server that uses custom linear padding: each message is padded as `a*m + b` before encryption, where a and b vary but the underlying message m stays constant. We can obtain two ciphertexts encrypted with the same n and e=11.

---

## Vulnerability

When two messages have a known linear relationship and are encrypted with the same RSA key, Franklin-Reiter's Related Message Attack applies. Given:
- c₁ = (a₁·m + b₁)^e mod n
- c₂ = (a₂·m + b₂)^e mod n

We can recover m using polynomial GCD.

---

## Solution

The attack uses polynomial GCD over ℤ/nℤ:

```sage
# Given: c1, c2 from encryptions of (a1*m + b1) and (a2*m + b2)
R.<x> = PolynomialRing(Zmod(N))

# Construct polynomials where x = m
f1 = (a1*x + b1)^e - c1
f2 = (a2*x + b2)^e - c2

# Euclidean GCD algorithm for polynomials
def poly_gcd(f, g):
    while g != 0:
        f, g = g, f % g
    return f.monic()

# GCD reveals the common root
gcd_poly = poly_gcd(f1, f2)

# Linear GCD means: x - m = 0, so m = -constant_term
if gcd_poly.degree() == 1:
    m = -gcd_poly.constant_coefficient()
    flag = int(m).to_bytes((int(m).bit_length() + 7) // 8, 'big')
```

The GCD of f₁ and f₂ is (x - m) since both polynomials share the root m.

---

## Key Takeaway

**Avoid linear relationships between plaintexts.** The Franklin-Reiter attack demonstrates that:
- Known algebraic relationships between messages leak information
- Proper randomized padding (like OAEP) prevents this class of attacks
- The attack works regardless of the exponent size (works for e=11, e=65537, etc.)

Custom padding schemes often have subtle vulnerabilities that standard schemes avoid.
