# Hash Stuffing (50 pts)

**Category:** Hash Functions — Collisions
**Difficulty:** Medium

---

## Challenge

Create two messages with identical MD5 hashes where:
- Message 1 contains "My favorite color is blue"
- Message 2 contains "My favorite color is red"

---

## Vulnerability

This requires a **chosen-prefix collision**: two messages with different prefixes that can be extended to have the same hash.

**Chosen-prefix collision:**
```
MD5(prefix1 || stuff1 || collision_blocks) = MD5(prefix2 || stuff2 || collision_blocks)
```

Tools like **HashClash** can generate such collisions.

---

## Solution

```python
# Using HashClash for chosen-prefix collision
# 1. Create prefix files
prefix1 = b"My favorite color is blue"
prefix2 = b"My favorite color is red"

# 2. Run HashClash (takes hours on CPU)
# $ ./hashclash prefix1.bin prefix2.bin

# 3. Result: two files with same MD5 but different prefixes
```

**Key insight:** The challenge title "Hash Stuffing" hints that MD5 padding is involved. MD5 always adds padding, even when the message is already block-aligned (512 bits = 64 bytes).

```python
# MD5 padding structure
# message || 0x80 || zeros || length_in_bits (8 bytes, little-endian)
# Total must be multiple of 64 bytes

# Even if message is exactly 64 bytes, padding adds another full block!
```

---

## Key Takeaway

**MD5 chosen-prefix collisions enable practical attacks:**
1. Rogue CA certificates (demonstrated in 2008)
2. Software update hijacking
3. Any context where attacker controls part of the message

The challenge name reminds us: **MD5 padding is always added**, which is important for length extension and collision attacks.
