# Salty (20 pts)

**Category:** RSA — Public Exponent
**Difficulty:** Easy

---

## Challenge

An RSA implementation uses "the smallest exponent for fastest encryption."

---

## Vulnerability

Using e = 1 means encryption does nothing: c = m^1 mod n = m (assuming m < n). The ciphertext IS the plaintext.

**Key insight:** There's no encryption when e = 1. This references the SaltStack CVE where improper crypto allowed authentication bypass.

---

## Solution

```python
def long_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

n = ...  # given
e = 1
ct = ...

# With e=1: c = m^1 mod n = m
m = ct  # Ciphertext IS the plaintext!
flag = long_to_bytes(m)
```

---

## Key Takeaway

**RSA requires e > 1 and specific constraints.** Valid public exponents must:
- Be greater than 1
- Be coprime to φ(n)
- Typically be 65537 (0x10001) or 3

e = 1 provides zero security—a lesson from real-world vulnerabilities like SaltStack's authentication bypass.

