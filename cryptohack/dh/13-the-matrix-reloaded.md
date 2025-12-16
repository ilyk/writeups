# The Matrix Reloaded (100 pts)

**Category:** Diffie-Hellman — Matrix Trilogy
**Difficulty:** Hard

> *"It's happening exactly as before... Well, not exactly."*

---

## Challenge

Matrix Diffie-Hellman over a large prime field:
- Generator: 30×30 matrix G over GF(P), where P is 512-bit prime
- Secret: H = G^SECRET
- Given: vectors v and w where w = H·v
- Goal: Find SECRET

---

## Background: Matrix DH

Standard DH uses scalar exponentiation: `A = g^a mod p`

Matrix DH uses matrix exponentiation: `H = G^SECRET mod P`

The discrete log problem in GL(n, GF(p)) is generally hard, but special matrix structures can make it tractable.

---

## Attack: Jordan Normal Form

The key insight: matrix exponentiation has special structure in Jordan canonical form.

**For a 2×2 Jordan block with eigenvalue λ:**
```
J = [λ  1]      J^k = [λ^k      k·λ^(k-1)]
    [0  λ]            [0        λ^k      ]
```

The off-diagonal element is **linear in k**! This allows direct extraction of the exponent.

---

## Mathematical Details

1. **Compute Jordan form:** G = P·J·P^(-1) where J has Jordan blocks

2. **Transform vectors:**
   ```
   v_J = P^(-1)·v
   w_J = P^(-1)·w
   ```

3. **For a Jordan block at position (i, i+1) with eigenvalue λ:**
   ```
   w_J[i+1] = λ^SECRET · v_J[i+1]
   w_J[i] = λ^SECRET·v_J[i] + SECRET·λ^(SECRET-1)·v_J[i+1]
   ```

4. **Extract SECRET:**
   ```
   λ^SECRET = w_J[i+1] / v_J[i+1]
   SECRET = (w_J[i] - λ^SECRET·v_J[i]) · λ / (λ^SECRET · v_J[i+1])
   ```

---

## Solution (SageMath)

```python
#!/usr/bin/env sage
import json

P = 13322168333598193507807385110954579994...  # 512-bit prime
N = 30

# Load data
G = Matrix(GF(P), rows)
v = vector(GF(P), output['v'])
w = vector(GF(P), output['w'])

# Compute Jordan form
J, P_mat = G.jordan_form(transformation=True)
P_inv = P_mat.inverse()

# Transform to Jordan basis
v_J = P_inv * v
w_J = P_inv * w

# Find Jordan block and extract SECRET
for i in range(N-1):
    if J[i,i+1] == 1:  # Found Jordan block
        lam = J[i,i]

        # λ^SECRET from element (i+1)
        lam_to_SECRET = w_J[i+1] / v_J[i+1]

        # SECRET from element (i) using linearity
        SECRET_times_lam = (w_J[i] - lam_to_SECRET * v_J[i]) / v_J[i+1]
        SECRET = ZZ(SECRET_times_lam * lam / lam_to_SECRET)

        # Verify
        if G^SECRET * v == w:
            print(f"SECRET = {SECRET}")
            break
```

---

## Running with Docker

```bash
docker pull sagemath/sagemath
docker run --rm -v $(pwd):/work -w /work sagemath/sagemath sage solver.sage
```

---

## Key Takeaway

**Jordan Normal Form transforms matrix DLP into a tractable problem:**

| Element | Standard DLP | Jordan Form |
|---------|--------------|-------------|
| Diagonal | λ^k | λ^k (standard DLP) |
| Off-diagonal | — | k·λ^(k-1) (**linear in k!**) |

The off-diagonal entries give us a linear equation in the exponent, bypassing the discrete log entirely.

**Requirements:** SageMath for Jordan form computation over large finite fields.
