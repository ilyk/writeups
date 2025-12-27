# Ellipse Curve Cryptography (125 pts)

**Category:** Mathematics — Brainteasers Part 2
**Difficulty:** Medium

---

## Challenge

Implement a Diffie-Hellman key exchange using a Pell conic (not an elliptic curve!) defined by x² - Dy² = 1 over a finite field.

---

## Vulnerability

The Pell conic x² - Dy² = 1 forms a group under the "addition" law:
```
(x₁, y₁) + (x₂, y₂) = (x₁x₂ + Dy₁y₂, x₁y₂ + x₂y₁)
```

**Key insight:** When D is a perfect square (D = 23² = 529), the Pell conic is isomorphic to the multiplicative group F_p*.

The mapping is: `(x, y) → x + √D·y = x + 23y (mod p)`

This reduces the DLP on the conic to a standard DLP in F_p*, which can be solved with Pohlig-Hellman when p-1 is smooth.

---

## Solution

```python
from sympy.ntheory import discrete_log

p = ...  # prime from challenge
D = 529  # = 23²
G = (gx, gy)  # generator point
alice_pub = (ax, ay)
bob_pub = (bx, by)

# Map Pell conic points to F_p*
def point_to_fp(pt):
    x, y = pt
    return (x + 23 * y) % p

G_z = point_to_fp(G)
alice_z = point_to_fp(alice_pub)

# Solve DLP in F_p*
alice_priv = discrete_log(p, alice_z, G_z)

# Compute shared secret
bob_z = point_to_fp(bob_pub)
shared_z = pow(bob_z, alice_priv, p)

# Decrypt flag with shared_z
```

---

## Key Takeaway

**Not all "curves" are created equal.** Pell conics with square D parameter collapse to trivial groups. When analyzing custom cryptographic curves:

1. Check if parameters create degenerate cases
2. Look for isomorphisms to known groups
3. The Pell conic with perfect square D is birationally equivalent to the multiplicative group

This demonstrates why standard elliptic curves use carefully chosen parameters to avoid such weaknesses.
