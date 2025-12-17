# Hash Functions Challenges

**Platform:** CryptoHack
**Category:** Hash Functions

Writeups for CryptoHack Hash Functions challenges covering birthday attacks, MD5 collisions, length extension, preimage attacks, and hash-based cryptography.

---

## Challenges

### Probability (2 challenges)
| # | Challenge | Points | Technique |
|---|-----------|--------|-----------|
| 01 | [Jack's Birthday Hash](01-jacks-birthday-hash.md) | 20 | Birthday problem |
| 02 | [Jack's Birthday Confusion](02-jacks-birthday-confusion.md) | 30 | Birthday problem |

### Collisions (5 challenges)
| # | Challenge | Points | Technique |
|---|-----------|--------|-----------|
| 03 | [Collider](03-collider.md) | 50 | MD5 collision pairs |
| 04 | [Hash Stuffing](04-hash-stuffing.md) | 50 | Chosen-prefix collision |
| 05 | [PriMeD5](05-primed5.md) | 100 | Collision + primality |
| - | Twin Keys | 100 | Not solved |
| 06 | [No Difference](06-no-difference.md) | 175 | UniColl PDF collision |

### Length Extension (2 challenges)
| # | Challenge | Points | Technique |
|---|-----------|--------|-----------|
| 07 | [MD0](07-md0.md) | 80 | Merkle-Damgard extension |
| - | MDFlag | 125 | Not solved |

### Pre-image (2 challenges)
| # | Challenge | Points | Technique |
|---|-----------|--------|-----------|
| 08 | [Mixed Up](08-mixed-up.md) | 120 | Algebraic weakness |
| 09 | [Invariant](09-invariant.md) | 250 | Invariant subspace |

### Hash-based Crypto (3 challenges)
| # | Challenge | Points | Technique |
|---|-----------|--------|-----------|
| 10 | [Merkle Trees](10-merkle-trees.md) | 25 | Proof verification |
| 11 | [WOTS Up](11-wots-up.md) | 75 | Signature forgery |
| 12 | [WOTS Up 2](12-wots-up-2.md) | 90 | Checksum bypass |

---

## Tools & Dependencies

- **Python:** hashlib, pycryptodome, pwntools, hashpumpy
- **Collision tools:** fastcoll, HashClash

---

**Completed: 12/14 challenges, 1065/1290 points (82.6%)**
