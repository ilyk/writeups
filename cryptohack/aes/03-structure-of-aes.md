# Structure of AES (15 pts)

**Category:** AES — How AES Works
**Difficulty:** Easy

---

## Challenge

Understand how AES organizes the 16-byte state internally.

---

## Vulnerability

AES operations work on a 4×4 matrix of bytes called the state. Understanding this structure is essential for implementing and attacking AES.

**Key insight:** The 16 input bytes are arranged column-wise into a 4×4 matrix, not row-wise.

---

## Solution

```python
def bytes_to_matrix(block):
    """Convert 16 bytes to 4x4 state matrix (column-major)"""
    return [list(block[i:i+4]) for i in range(0, 16, 4)]

# AES arranges bytes column-wise:
# input:  [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15]
#
# matrix: | b0  b4  b8  b12 |
#         | b1  b5  b9  b13 |
#         | b2  b6  b10 b14 |
#         | b3  b7  b11 b15 |
```

---

## Key Takeaway

**AES uses column-major state ordering.** This affects:
- ShiftRows operates on rows (horizontal shifting)
- MixColumns operates on columns (vertical mixing)
- Byte positions matter for attacks like differential cryptanalysis
- Implementation bugs often stem from incorrect byte ordering

