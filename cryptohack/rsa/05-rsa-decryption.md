# RSA Decryption (20 pts)

**Category:** RSA — Starter
**Difficulty:** Easy

---

## Challenge

Decrypt an RSA ciphertext using the private key.

---

## Vulnerability

RSA decryption mirrors encryption: `m = c^d mod n`. With the private key, decryption is as simple as modular exponentiation.

**Key insight:** The mathematical relationship `(m^e)^d ≡ m (mod n)` ensures encryption is reversible.

---

## Solution

```python
n = 882564595536224140639625987659416029426239230804614613279163
e = 65537
c = 77578995801157823671636298847186723593814843845525223303932  # ciphertext

# First, factor n (for this challenge, factors are given or small enough to factor)
p = 857504083339712752489993810777
q = 1029224947942998075080348647219

# Compute private key
phi_n = (p - 1) * (q - 1)
d = pow(e, -1, phi_n)

# Decrypt: m = c^d mod n
m = pow(c, d, n)
print(m)
```

---

## Key Takeaway

**RSA decryption is just exponentiation with the private exponent.** The security model:
- Anyone with (n, e) can encrypt
- Only the holder of d can decrypt
- d is computationally infeasible to derive from (n, e) alone

This asymmetry enables secure communication without pre-shared secrets.

