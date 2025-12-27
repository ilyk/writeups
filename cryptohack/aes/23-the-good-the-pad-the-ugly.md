# The Good, The Pad, The Ugly (100 pts)

**Category:** AES — Padding Attacks
**Difficulty:** Hard

---

## Challenge

Exploit a faulty padding oracle that sometimes gives incorrect responses.

---

## Vulnerability

Even an unreliable padding oracle can be exploited through statistical analysis. Multiple queries for each guess can overcome noise.

**Key insight:** If the oracle is correct 90% of the time, querying 10+ times and taking the majority vote gives high confidence.

---

## Solution

```python
def noisy_oracle_attack(ciphertext, oracle, queries_per_byte=10):
    """Handle unreliable padding oracle with voting"""
    block_size = 16

    def reliable_check(test_ct):
        """Query multiple times and vote"""
        results = [oracle(test_ct) for _ in range(queries_per_byte)]
        return sum(results) > queries_per_byte // 2

    # Standard padding oracle attack but with reliable_check()
    for block_num in range(len(ciphertext) // block_size - 1, 0, -1):
        # ... same structure as standard attack ...
        for guess in range(256):
            prev_block[byte_pos] = guess
            if reliable_check(bytes(prev_block) + block):
                # Additional validation to confirm
                # (flip other bits to ensure it's not a false positive)
                pass
```

---

## Key Takeaway

**Noisy oracles can still be exploited.** Countermeasures:
- Rate limiting (makes statistical attacks slower but not impossible)
- Account lockout (stops attack but causes DoS)
- Authenticated encryption (eliminates oracle entirely)

The fundamental issue is information leakage—any distinguishable response enables attacks.

