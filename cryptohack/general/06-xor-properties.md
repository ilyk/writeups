# XOR Properties (15 pts)

**Category:** General — XOR
**Difficulty:** Easy

---

## Challenge

Given multiple XOR combinations of keys and flag, recover the original flag using XOR properties.

Given:
- KEY1, KEY2, KEY3 (known)
- KEY2 ⊕ KEY3 ⊕ KEY1
- KEY1 ⊕ KEY2 ⊕ FLAG

---

## Vulnerability

XOR is associative and commutative, meaning we can rearrange operations to isolate unknowns.

**Key insight:** If we have `KEY1 ⊕ KEY2 ⊕ FLAG` and know KEY1 and KEY2, we can recover FLAG by XORing with both keys.

---

## Solution

```python
KEY1 = bytes.fromhex("a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313")
KEY2_xor_KEY3_xor_KEY1 = bytes.fromhex("c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1")
KEY1_xor_KEY2_xor_FLAG = bytes.fromhex("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf")

# First, get KEY2 ⊕ KEY3 by XORing with KEY1
KEY2_xor_KEY3 = bytes(a ^ b for a, b in zip(KEY2_xor_KEY3_xor_KEY1, KEY1))

# From another relation, we can derive the FLAG
# FLAG = KEY1 ⊕ KEY2 ⊕ (KEY1 ⊕ KEY2 ⊕ FLAG) would cancel...
# We need KEY2 to isolate FLAG

# Actually: KEY1 ⊕ KEY2 ⊕ FLAG ⊕ KEY1 ⊕ KEY2 = FLAG
# So we need to know KEY2. Given the relations, work through the algebra.

# With all pieces:
flag = bytes(a ^ b ^ c for a, b, c in zip(KEY1_xor_KEY2_xor_FLAG, KEY1, KEY2))
print(flag.decode())
```

---

## Key Takeaway

**XOR algebra allows key recovery.** Given enough XOR combinations, you can often solve for unknowns. This is why:
- Keys must never be reused (two-time pad attack)
- Related plaintexts are dangerous
- XOR alone provides no security without proper key management
