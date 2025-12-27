# Round Keys (20 pts)

**Category:** AES — How AES Works
**Difficulty:** Easy

---

## Challenge

Understand AES key expansion and how round keys are derived from the master key.

---

## Vulnerability

AES key schedule derives round keys from the master key. Weaknesses in key scheduling can enable related-key attacks.

**Key insight:** Each round uses a different key derived through XOR operations, S-box substitution, and round constants.

---

## Solution

```python
def expand_key(master_key):
    """AES-128 key expansion"""
    # Round constants
    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    # Split master key into 4-byte words
    key_words = [master_key[i:i+4] for i in range(0, 16, 4)]

    # Expand to 44 words (11 round keys × 4 words each)
    for i in range(4, 44):
        temp = key_words[i-1]
        if i % 4 == 0:
            # RotWord, SubWord, XOR with Rcon
            temp = sub_word(rot_word(temp))
            temp[0] ^= rcon[i//4 - 1]
        key_words.append(xor_bytes(key_words[i-4], temp))

    return key_words
```

---

## Key Takeaway

**Key scheduling must resist related-key attacks.** AES key schedule:
- Produces 11 round keys for AES-128 (10 rounds + initial)
- Uses non-linear operations (S-box) for security
- Round constants prevent slide attacks
- Related-key attacks exist for AES-256 (reduced rounds)

