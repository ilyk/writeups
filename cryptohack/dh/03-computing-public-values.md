# Computing Public Values (25 pts)

**Category:** Diffie-Hellman — Starter
**Difficulty:** Easy

---

## Challenge

Compute the public value in Diffie-Hellman key exchange given the generator, private key, and prime.

---

## Solution

In DH, each party computes their public value:
```
A = g^a mod p
```

Where:
- `g` is the generator
- `a` is the private key (secret)
- `p` is the prime modulus

```python
def compute_public_value(g, a, p):
    return pow(g, a, p)

# Example
g = 2
p = 0xFFFFFFFFFFFFFFFFC90FDAA2...  # Large safe prime
a = <private_key>

A = pow(g, a, p)
```

---

## Key Takeaway

The security of DH relies on the **discrete logarithm problem (DLP)**: given `g`, `p`, and `A = g^a mod p`, finding `a` is computationally infeasible for properly chosen parameters.
