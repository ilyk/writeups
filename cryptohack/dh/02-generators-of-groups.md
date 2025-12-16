# Generators of Groups (20 pts)

**Category:** Diffie-Hellman — Starter
**Difficulty:** Easy

---

## Challenge

Find the smallest generator of a multiplicative group modulo a prime p.

---

## Solution

A generator `g` of the multiplicative group (Z/pZ)* has order `p-1`, meaning:
- g^k ≠ 1 for all k < p-1
- g^(p-1) = 1

To verify if `g` is a generator, check that `g^((p-1)/q) ≠ 1` for all prime factors `q` of `p-1`.

```python
from sympy import factorint

def is_generator(g, p):
    order = p - 1
    factors = factorint(order)

    for q in factors:
        if pow(g, order // q, p) == 1:
            return False
    return True

def find_smallest_generator(p):
    for g in range(2, p):
        if is_generator(g, p):
            return g
```

---

## Key Takeaway

Not all elements are generators. The number of generators equals φ(p-1) (Euler's totient of p-1). For secure DH, the generator must have large prime order.
