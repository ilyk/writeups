# Favourite Byte (10 pts)

**Category:** General — XOR
**Difficulty:** Easy

---

## Challenge

A message has been XORed with a single byte. Recover the original message.

---

## Vulnerability

Single-byte XOR is trivially breakable by brute force—there are only 256 possible keys. Additionally, we can use frequency analysis or look for known plaintext patterns.

**Key insight:** The flag format `crypto{...}` gives us a known plaintext crib to validate our guess.

---

## Solution

```python
ciphertext = bytes.fromhex("73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d")

# Brute force all 256 possible single-byte keys
for key in range(256):
    plaintext = bytes(b ^ key for b in ciphertext)
    # Check if result looks like valid ASCII/flag format
    if plaintext.startswith(b"crypto{"):
        print(f"Key: {key} (0x{key:02x})")
        print(f"Plaintext: {plaintext.decode()}")
        break
```

---

## Key Takeaway

**Single-byte XOR provides no real security.** With only 256 possibilities, exhaustive search is instant. This attack extends to:
- Repeating-key XOR (solve byte-by-byte)
- Any cipher with small key space
- Frequency analysis when key is unknown but plaintext is natural language

