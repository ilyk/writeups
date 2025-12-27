# Real Eisenstein (150 pts)

**Category:** Mathematics — Brainteasers Part 2
**Difficulty:** Hard

---

## Challenge

The flag is encrypted as:
```python
ct = floor(sum(ord(c_i) * sqrt(p_i)) * 16^64)
```
where p_i are the first 27 primes and c_i are the 27 flag characters.

---

## Vulnerability

This is a subset-sum/knapsack problem solvable with LLL lattice reduction.

**Key insight:** The CJLOSS algorithm (Low-Density Attack) works for knapsack problems where the density d = n / log₂(max_weight) < 0.9408.

For ASCII characters (0-127), center the search at 64 (midpoint). This transforms the problem to finding small deltas where char_i = 64 + delta_i.

---

## Solution

```python
from decimal import Decimal, getcontext
getcontext().prec = 100

PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
          53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103]
ct = 1350995397927355657956786955603012410260017344805998076702828160316695004588429433
scale = Integer(16)^64
center = 64

# High precision square roots
R = RealField(500)
sqrts_int = [Integer(floor(sqrt(R(p)) * R(scale))) for p in PRIMES]
target = Integer(ct)

# CJLOSS lattice: find deltas such that sum((64+delta_i)*sqrt_i) ≈ ct
adjusted_target = target - center * sum(sqrts_int)

L = Matrix(ZZ, 28, 28)
for i in range(27):
    L[i, i] = 1
    L[i, 27] = sqrts_int[i]
L[27, 27] = -adjusted_target

# BKZ reduction with block size 20
L_reduced = L.BKZ(block_size=20)

# Search for valid ASCII solution
for row in L_reduced:
    deltas = [int(row[i]) for i in range(27)]
    for sign in [1, -1]:
        vals = [center + sign * d for d in deltas]
        if all(0 <= v <= 127 for v in vals):
            flag = ''.join(chr(v) for v in vals)
            if compute_ct(flag) == ct:
                print(f"FLAG: {flag}")
```

---

## Key Takeaway

**Lattice reduction solves hidden linear combinations.** The LLL/BKZ algorithms find short vectors in lattices, which translates to finding small coefficients in linear equations:

1. **Center at expected value** - for ASCII (0-127), use 64
2. **Scale appropriately** - square roots need sufficient precision
3. **Use BKZ for harder instances** - LLL alone may not find the solution

This technique applies to:
- NTRU cryptanalysis
- Subset-sum/knapsack problems
- Coppersmith's method for RSA attacks
- Recovering hidden secrets in LWE-based schemes
