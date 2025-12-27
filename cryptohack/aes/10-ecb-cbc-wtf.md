# ECB CBC WTF (55 pts)

**Category:** AES — Block Ciphers 1
**Difficulty:** Medium

---

## Challenge

An image was encrypted with AES-ECB. Identify the original image.

---

## Vulnerability

ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, preserving patterns in the data.

**Key insight:** Images have redundant data (large areas of same color), which creates visible patterns in ECB-encrypted output.

---

## Solution

```python
from PIL import Image

# Load the encrypted image
encrypted = Image.open("encrypted.png")
pixels = list(encrypted.getdata())

# ECB preserves block patterns
# Identical 16-byte blocks → identical ciphertext blocks
# Visual patterns in the image remain visible

# The famous "ECB penguin" demonstrates this:
# https://blog.filippo.io/the-ecb-penguin/
```

---

## Key Takeaway

**ECB mode leaks plaintext patterns.** Never use ECB for:
- Images or structured data
- Any data with repeated blocks
- Any data where pattern preservation is dangerous

ECB is only "safe" when each block is guaranteed unique (like encrypting random keys), but even then CBC/CTR are preferred.

