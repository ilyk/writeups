# Computing Shared Secrets (30 pts)

**Category:** Diffie-Hellman — Starter
**Difficulty:** Easy

---

## Challenge

Compute the shared secret in a Diffie-Hellman key exchange.

---

## Solution

After exchanging public values, both parties compute the same shared secret:

**Alice computes:**
```
s = B^a mod p = (g^b)^a mod p = g^(ab) mod p
```

**Bob computes:**
```
s = A^b mod p = (g^a)^b mod p = g^(ab) mod p
```

Both arrive at `s = g^(ab) mod p`.

```python
def compute_shared_secret(their_public, my_private, p):
    return pow(their_public, my_private, p)

# Alice's perspective
shared_secret = pow(B, a, p)

# Bob's perspective
shared_secret = pow(A, b, p)
```

---

## Key Takeaway

The magic of DH: both parties compute the same secret without ever transmitting it. An eavesdropper sees only `g`, `p`, `A`, and `B`—not enough to compute `g^(ab)` without solving DLP.
