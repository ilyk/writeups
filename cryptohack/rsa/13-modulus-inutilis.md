# Modulus Inutilis (50 pts)

**Category:** RSA — Public Exponent
**Difficulty:** Easy

---

## Challenge

RSA with e = 3 and a "very large modulus" that should be secure.

---

## Vulnerability

When e = 3 and the message m is small enough that m³ < n, no modular reduction occurs. The ciphertext c = m³ exactly, recoverable by cube root.

**Key insight:** "Modulus Inutilis" (Latin: "useless modulus") hints that n is irrelevant when m^e < n.

---

## Solution

```python
def integer_nthroot(n, k):
    """Compute k-th root using Newton's method"""
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        x1 = ((k - 1) * x + n // (x ** (k - 1))) // k
        if x1 >= x:
            return x
        x = x1

e = 3
ct = ...  # given

# m^3 < n, so c = m^3 exactly
m = integer_nthroot(ct, 3)
assert m ** 3 == ct  # Verify exact cube
```

---

## Key Takeaway

**Small exponents require proper padding.** The attack fails when:
- m is padded to be close to n in size
- OAEP padding adds randomness
- m^e is guaranteed to exceed n

This is why PKCS#1 v1.5 and OAEP padding exist—raw RSA with small e is dangerous.

