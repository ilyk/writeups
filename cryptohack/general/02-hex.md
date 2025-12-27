# Hex (5 pts)

**Category:** General — Encoding
**Difficulty:** Easy

---

## Challenge

Decode a hexadecimal string to reveal the hidden message.

---

## Vulnerability

Hexadecimal is base-16 encoding where each byte is represented as two hex characters (0-9, a-f). It's commonly used in cryptography because it's more compact than binary and maps cleanly to bytes.

**Key insight:** `bytes.fromhex()` converts hex strings to bytes, and `.hex()` does the reverse.

---

## Solution

```python
hex_string = "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"

# Decode hex to bytes, then to string
message = bytes.fromhex(hex_string).decode()
print(message)
```

---

## Key Takeaway

**Hex encoding is ubiquitous in cryptography.** Keys, hashes, ciphertexts, and raw binary data are almost always displayed in hex format. Master the conversions: `bytes.fromhex()`, `.hex()`, and format strings like `f"{value:02x}"`.
