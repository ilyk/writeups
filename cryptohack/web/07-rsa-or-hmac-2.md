# RSA or HMAC? Part 2 (100 pts)

**Category:** JSON Web Tokens
**Difficulty:** Hard

---

## Challenge

Similar to Part 1, the server accepts both RS256 and HS256 algorithms. However, there's no `/get_pubkey/` endpoint - we must recover the RSA public key from the JWT signatures themselves.

**Endpoints:**
- `/rsa-or-hmac-2/create_session/<username>/` - Create RS256-signed session
- `/rsa-or-hmac-2/authorise/<token>/` - Authorize with a token

---

## The Attack: RSA Public Key Recovery

RSA signatures follow the relationship: `s = m^d mod n`

Which means: `s^e ≡ m (mod n)`

Therefore: `s^e - m ≡ 0 (mod n)`

If we have two different message-signature pairs (m1, s1) and (m2, s2):
- `s1^e - m1 ≡ 0 (mod n)`
- `s2^e - m2 ≡ 0 (mod n)`

The GCD of `(s1^e - m1)` and `(s2^e - m2)` will be `n` (or a multiple of `n`).

---

## Step 1: Collect JWT Signatures

```python
import requests
import base64
import hashlib

tokens = []
for username in ['user1', 'user2']:
    url = f"https://web.cryptohack.org/rsa-or-hmac-2/create_session/{username}/"
    token = requests.get(url).json()['session']
    tokens.append(token)
```

---

## Step 2: Extract Message and Signature

RS256 uses PKCS#1 v1.5 padding with SHA-256:

```python
def extract_jwt_parts(token):
    parts = token.split('.')
    header_payload = f"{parts[0]}.{parts[1]}"
    sig_b64 = parts[2] + '=' * (4 - len(parts[2]) % 4)
    sig = base64.urlsafe_b64decode(sig_b64)
    return header_payload, sig

def pkcs1_v15_encode(message_hash, key_size_bytes=256):
    """PKCS#1 v1.5 encoding for SHA-256"""
    digest_info = bytes([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                         0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                         0x00, 0x04, 0x20]) + message_hash
    pad_len = key_size_bytes - 3 - len(digest_info)
    padded = b'\x00\x01' + (b'\xff' * pad_len) + b'\x00' + digest_info
    return int.from_bytes(padded, 'big')
```

---

## Step 3: Compute GCD to Find n

Using gmpy2 for efficient large integer arithmetic:

```python
import gmpy2
from gmpy2 import mpz, gcd

e = 65537  # Standard RSA public exponent

# Compute s^e for each signature
s1_e = mpz(s1) ** e
s2_e = mpz(s2) ** e

# GCD recovers n
v1 = s1_e - m1
v2 = s2_e - m2
n = gcd(v1, v2)
```

---

## Step 4: Algorithm Confusion Attack

Once we have `n`, construct the public key and use it as an HMAC secret:

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

# Create public key
public_numbers = RSAPublicNumbers(e, n)
public_key = public_numbers.public_key()

# Export as PKCS1 PEM (critical: must match server's key format!)
pem_pkcs1 = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1
)

# Sign with HMAC using the PEM as secret
import hmac
signature = hmac.new(pem_pkcs1, message, hashlib.sha256).digest()
```

**Important:** The PEM format must match what the server uses. In this case, PKCS1 format (not SubjectPublicKeyInfo) was required.

---

## Key Insights

1. **RSA public keys can be recovered from signatures** - With two signatures, GCD of `(s^e - m)` values yields `n`

2. **Computing `s^65537` is expensive but feasible** - Results in ~134 million bit numbers, but gmpy2 handles it in ~30 seconds

3. **PEM format matters** - Different key serialization formats (PKCS1 vs SPKI) produce different byte sequences for HMAC

---

## References

- [rsa_sign2n](https://github.com/silentsignal/rsa_sign2n) - Tool for RSA key recovery from signatures
- [Silent Signal Blog](https://blog.silentsignal.eu/2021/02/08/abusing-jwt-public-keys-without-the-public-key/) - "Abusing JWT public keys without the public key"
- [JWT-Key-Recovery](https://github.com/FlorianPicca/JWT-Key-Recovery) - Alternative recovery tool
