# Marin's Secrets (50 pts)

**Category:** RSA — Primes Part 2
**Difficulty:** Medium

---

## Challenge

An RSA modulus that contains a special prime with a familiar structure. The name references Marin Mersenne.

---

## Vulnerability

One prime factor is a Mersenne prime (of the form 2^p - 1). Since only 51 Mersenne primes are known, we can simply test if n is divisible by each one.

**Key insight:** Mersenne primes are rare and well-catalogued. Using one in RSA makes the modulus trivially factorable by trial division against the known list.

---

## Solution

```python
# Known Mersenne prime exponents
mersenne_exponents = [
    2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607,
    1279, 2203, 2281, 3217, 4253, 4423, 9689, 9941, 11213,
    19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091,
    756839, 859433, 1257787, 1398269, 2976221, 3021377, 6972593,
    13466917, 20996011, 24036583, 25964951, 30402457, 32582657,
    37156667, 42643801, 43112609, 57885161, 74207281, 77232917,
    82589933
]

def find_mersenne_factor(n):
    for exp in mersenne_exponents:
        mp = (1 << exp) - 1  # 2^exp - 1
        if n % mp == 0:
            return mp, n // mp
    return None

n = ...  # given
e = 65537
ct = ...

p, q = find_mersenne_factor(n)
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(ct, d, n)
```

---

## Key Takeaway

**Never use special-form primes.** Mersenne, Fermat, and other structured primes are:
- Easily enumerable (only 51 known Mersenne primes)
- Quickly testable via trial division
- A single lookup table breaks the key

RSA primes should be randomly generated with no special mathematical structure.

