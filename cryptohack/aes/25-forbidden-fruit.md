# Forbidden Fruit (150 pts)

**Category:** AES — Authenticated Encryption
**Difficulty:** Hard

---

## Challenge

Exploit a nonce reuse vulnerability in AES-GCM.

---

## Vulnerability

AES-GCM uses a counter mode for encryption and GHASH for authentication. Reusing a nonce with the same key allows authentication key (H) recovery and forgery.

**Key insight:** With two messages encrypted under the same nonce, `C1 ⊕ C2 = P1 ⊕ P2`. The authentication tags can be used to solve for the GHASH key H.

---

## Solution

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long

def gcm_nonce_reuse_attack(ct1, tag1, ct2, tag2, aad1, aad2):
    """
    GCM tag: GHASH(AAD || CT || lengths) ⊕ E(nonce||0)

    With same nonce:
    tag1 ⊕ tag2 = GHASH1(data1) ⊕ GHASH2(data2)

    GHASH is polynomial evaluation in GF(2^128):
    GHASH(blocks) = b[n]*H^n + b[n-1]*H^(n-1) + ... + b[1]*H

    Tag difference gives polynomial equation in H
    Solve for H using GF(2^128) arithmetic
    """
    # Build polynomial from tag difference
    # Find roots in GF(2^128) to recover H
    # With H, forge tags for arbitrary messages
    pass
```

---

## Key Takeaway

**GCM nonce reuse is catastrophic.** Consequences:
- Authentication key H recovered
- Can forge valid tags for any message
- XOR of plaintexts revealed

Prevention: Use random 96-bit nonces (birthday bound at 2^48 messages) or deterministic nonces with strict uniqueness guarantees.

