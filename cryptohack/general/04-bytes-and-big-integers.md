# Bytes and Big Integers (10 pts)

**Category:** General — Encoding
**Difficulty:** Easy

---

## Challenge

Convert a large integer back to its original message.

---

## Vulnerability

Cryptographic operations work on integers, but messages are bytes. The standard conversion treats the byte string as a big-endian number.

**Key insight:** A message like "HELLO" becomes the integer `0x48454c4c4f` = 310939249735.

---

## Solution

```python
def long_to_bytes(n):
    """Convert integer to bytes (big-endian)"""
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

n = 11515195063862318899931685488813747395775516287289682636499965282714637259206269

message = long_to_bytes(n).decode()
print(message)
```

---

## Key Takeaway

**Integer ↔ bytes conversion is fundamental to RSA and other cryptosystems.** Know these functions:
- `int.from_bytes(b, 'big')` — bytes to integer
- `n.to_bytes(length, 'big')` — integer to bytes
- PyCryptodome provides `Crypto.Util.number.long_to_bytes()` and `bytes_to_long()`

The bit length calculation `(n.bit_length() + 7) // 8` gives the minimum bytes needed to represent the integer.
