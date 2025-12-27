# ASCII (5 pts)

**Category:** General — Encoding
**Difficulty:** Easy

---

## Challenge

Convert a list of ASCII decimal values back to the original message.

---

## Vulnerability

This is an introductory challenge demonstrating basic character encoding. ASCII (American Standard Code for Information Interchange) maps integers 0-127 to characters.

**Key insight:** Python's `chr()` function converts integers to characters, and `ord()` does the reverse.

---

## Solution

```python
# Given ASCII values
ascii_values = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67,
                73, 73, 95, 112, 114, 49, 110, 116, 52, 98,
                108, 51, 125]

# Convert to string
message = ''.join(chr(x) for x in ascii_values)
print(message)
```

---

## Key Takeaway

**Understanding character encodings is fundamental to cryptography.** All cryptographic operations work on bytes/numbers, so conversion between text and numeric representations is essential. ASCII is the simplest encoding; UTF-8 extends it for international characters.
