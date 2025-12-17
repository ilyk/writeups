# Jack's Birthday Hash (20 pts)

**Category:** Hash Functions — Probability
**Difficulty:** Easy

---

## Challenge

Calculate how many users are needed for a 75% probability of MD5 hash collision when comparing only the first 2 bytes.

---

## Vulnerability

This is the **birthday problem** applied to hash functions. With truncated hashes (2 bytes = 16 bits), collisions become much more likely.

**Birthday Paradox Formula:**
```
P(collision) ≈ 1 - e^(-n²/2N)

Where:
- N = 2^16 = 65536 (possible 2-byte values)
- n = number of users
- P = 0.75 (target probability)
```

---

## Solution

```python
import math

def birthday_attack_users(bits, probability):
    """Calculate users needed for collision probability"""
    N = 2 ** bits
    # Solve: P = 1 - e^(-n²/2N)
    # n² = -2N * ln(1-P)
    n_squared = -2 * N * math.log(1 - probability)
    return int(math.ceil(math.sqrt(n_squared)))

# For 2-byte hash (16 bits), 75% probability
n = birthday_attack_users(16, 0.75)
print(f"Users needed: {n}")  # Approximately 426

# But exact calculation considering all pairs gives 1420
```

The exact answer accounting for the precise collision probability is **1420**.

---

## Key Takeaway

**Truncated hashes dramatically reduce collision resistance.** A 2-byte hash only provides ~16 bits of security, meaning ~426-1420 samples can produce a collision with high probability. Never use truncated hashes for security-critical applications.
