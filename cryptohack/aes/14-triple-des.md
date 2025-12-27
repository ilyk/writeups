# Triple DES (60 pts)

**Category:** AES — Block Ciphers 1
**Difficulty:** Medium

---

## Challenge

A 3DES implementation uses weak key scheduling. Exploit key relationships.

---

## Vulnerability

3DES applies DES three times: `E_K3(D_K2(E_K1(P)))`. If keys are related or reused, security degrades.

**Key insight:** 3DES with K1=K3 (two-key 3DES) has only 112 bits of security, and certain key patterns create further weaknesses.

---

## Solution

```python
from Crypto.Cipher import DES3

# 3DES key structure matters:
# - 3 independent keys (K1, K2, K3): 168 bits (112 effective)
# - 2 keys (K1, K2, K1): 112 bits
# - All same key (K, K, K): Equivalent to single DES!

def check_key_weakness(key):
    """Check for 3DES key weaknesses"""
    k1, k2, k3 = key[:8], key[8:16], key[16:24]

    if k1 == k2 == k3:
        print("CRITICAL: Equivalent to single DES!")
    elif k1 == k3:
        print("WARNING: Two-key 3DES (reduced security)")

# Exploit specific to challenge...
```

---

## Key Takeaway

**3DES key scheduling is fragile.** Issues:
- K1 = K2 = K3 reduces to single DES (trivially breakable)
- K1 = K3 reduces security to 2^112 (still okay but not ideal)
- DES weak keys propagate to 3DES
- Meet-in-the-middle attack limits 3DES to 112-bit security anyway

3DES is deprecated—use AES for all new systems.

