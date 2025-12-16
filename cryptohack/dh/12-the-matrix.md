# The Matrix (75 pts)

**Category:** Diffie-Hellman — Matrix Trilogy
**Difficulty:** Medium

> *"I must get out of here. I must get free, and in this mind is the key, my key!"*

---

## Challenge

The flag is encoded in a 50×50 matrix `M` over GF(2). We're given:
- `ciphertext = M^E` where E = 31337
- Need to recover M

---

## Background: Matrix Groups over Finite Fields

Matrices over GF(2) form the **General Linear Group** GL(n, GF(2)). The group order is:
```
|GL(n, GF(2))| = ∏_{i=0}^{n-1} (2^n - 2^i)
```

For n=50, this is astronomically large but has known structure.

---

## Attack: Matrix Discrete Log via Inverse Exponent

Since `ciphertext = M^E`, we can recover M if we find `E^(-1) mod ord`:
```
M = ciphertext^(E^(-1) mod ord)
```

The multiplicative order of any matrix divides |GL(n, GF(2))|, so we can use the full group order as an upper bound.

---

## Solution

```python
import galois
import numpy as np

P, N, E = 2, 50, 31337

# Load ciphertext matrix
data = open('flag_matrix.enc', 'r').read().strip()
rows = [list(map(int, row)) for row in data.splitlines()]

GF2 = galois.GF(2)
ciphertext = GF2(rows)

# Compute |GL(50, GF(2))|
gl_order = 1
for i in range(N):
    gl_order *= (2**N - 2**i)

# Compute E^(-1) mod |GL|
E_inv = pow(E, -1, gl_order)

# Matrix power using repeated squaring
def matrix_power(M, exp):
    result = GF2.Identity(N)
    base = M.copy()
    while exp > 0:
        if exp & 1:
            result = result @ base
        base = base @ base
        exp >>= 1
    return result

# Recover original matrix
M = matrix_power(ciphertext, E_inv)

# Extract flag from matrix bits
# Flag is encoded column-wise
msg_bits = []
for col in range(N):
    for row in range(N):
        msg_bits.append(int(M[row, col]))

# Convert to bytes and find flag
```

---

## Key Takeaway

Matrix exponentiation over finite fields follows similar principles to scalar exponentiation:
- Multiplicative order divides group order
- Inverse exponents can recover original matrices
- Efficient computation via repeated squaring

**Tools:** Python `galois` library for GF(2) matrix operations.
