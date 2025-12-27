# Privacy-Enhanced Mail (PEM) (15 pts)

**Category:** Data Formats — Encoding
**Difficulty:** Easy

---

## Challenge

Extract the private exponent d from a PEM-encoded RSA private key.

---

## Vulnerability

PEM is a Base64 encoding of DER (Distinguished Encoding Rules) data, wrapped with header/footer lines. RSA private keys contain all the key components in a structured ASN.1 format.

**Key insight:** The private key file contains not just d, but all of: n, e, d, p, q, dp, dq, qinv. Any of these can be extracted using ASN.1 parsing.

---

## Solution

```python
from Crypto.PublicKey import RSA

# Read the PEM file
with open("private.pem", "r") as f:
    key_data = f.read()

# Parse the RSA key
key = RSA.import_key(key_data)

# Extract private exponent d
d = key.d
print(d)
```

Alternative using cryptography library:
```python
from cryptography.hazmat.primitives import serialization

with open("private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Get private numbers
private_numbers = private_key.private_numbers()
d = private_numbers.d
print(d)
```

---

## Key Takeaway

**PEM files expose all RSA parameters.** An RSA private key in PKCS#1 format contains:
- version, n, e, d, p, q, d mod (p-1), d mod (q-1), q^(-1) mod p

This redundancy enables CRT optimization for faster decryption. When handling private keys:
- Never expose them
- Use proper file permissions (chmod 600)
- Consider encrypted PEM (PKCS#8 with password)

