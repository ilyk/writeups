# You either know, XOR you don't (10 pts)

**Category:** General — XOR
**Difficulty:** Easy

---

## Challenge

A message has been XORed with a secret key. The flag format is known.

---

## Vulnerability

Known plaintext attacks devastate XOR encryption. If we know any part of the plaintext, we can recover the corresponding key bytes.

**Key insight:** Since `P ⊕ K = C`, we have `K = P ⊕ C`. Knowing that the flag starts with `crypto{` reveals the first 7 key bytes.

---

## Solution

```python
ciphertext = bytes.fromhex("0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104")

known_plaintext = b"crypto{"

# Recover key from known plaintext
key_fragment = bytes(c ^ p for c, p in zip(ciphertext, known_plaintext))
print(f"Key fragment: {key_fragment}")

# The key likely repeats - find the pattern
# Key appears to be "myXORkey" repeating
key = b"myXORkey"

# Decrypt with repeating key
plaintext = bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))
print(plaintext.decode())
```

---

## Key Takeaway

**Known plaintext is fatal to XOR.** This is why:
- Stream ciphers must never reuse keys (keystream recovery)
- File format headers are dangerous (known structure)
- The "two-time pad" attack works: `C1 ⊕ C2 = P1 ⊕ P2`

Modern stream ciphers use IVs/nonces to ensure unique keystreams even with the same key.

