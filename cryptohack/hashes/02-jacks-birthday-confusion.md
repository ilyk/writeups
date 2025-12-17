# Jack's Birthday Confusion (30 pts)

**Category:** Hash Functions — Probability
**Difficulty:** Easy

---

## Challenge

Find how many users are needed before Jack confuses two users based on MD5 hash collision in the first byte only.

---

## Vulnerability

Same birthday problem as before, but with only **1 byte = 8 bits** of hash output.

**Parameters:**
- N = 2^8 = 256 possible values
- Target: High collision probability

---

## Solution

```python
import math

def birthday_attack_users(bits, probability=0.5):
    """Calculate users for 50% collision probability (birthday bound)"""
    N = 2 ** bits
    # Birthday approximation: n ≈ 1.177 * sqrt(N)
    return int(math.ceil(1.177 * math.sqrt(N)))

# For 1-byte hash (8 bits)
n = birthday_attack_users(8)
print(f"Users needed: {n}")  # ~19 for 50%

# For higher probability, need more users
# At n=76, collision is almost certain
```

With only 256 possible values, approximately **76 users** creates near-certain collision probability.

---

## Key Takeaway

**Single-byte "hash" is essentially useless for identity.** With only 256 possible values, the birthday bound is ~19 users, and at 76 users collision is virtually guaranteed. This demonstrates why hash functions need sufficient output length.
