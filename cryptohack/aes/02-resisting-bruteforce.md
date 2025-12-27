# Resisting Bruteforce (10 pts)

**Category:** AES — How AES Works
**Difficulty:** Easy

---

## Challenge

Identify the best known attack against AES that is slightly faster than brute force.

---

## Vulnerability

Even a small theoretical weakness can undermine confidence in a cipher, though practical exploitation may be infeasible.

**Key insight:** The biclique attack reduces AES-128 security from 2^128 to approximately 2^126.1 operations—still far beyond practical reach.

---

## Solution

The answer is: **biclique**

The biclique attack (2011):
- Reduces AES-128 complexity from 2^128 to ~2^126.1
- Reduces AES-256 from 2^256 to ~2^254.4
- Uses meet-in-the-middle techniques with biclique structures
- Requires the full codebook (all 2^128 plaintexts)

---

## Key Takeaway

**Theoretical breaks don't always matter practically.** The biclique attack:
- Saves only ~4x work over brute force
- Still requires 2^126 operations (computationally infeasible)
- Requires impractical data complexity

AES remains secure for all practical purposes despite this theoretical weakness.

