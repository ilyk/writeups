# No Way JOSE (20 pts)

**Category:** JSON Web Tokens
**Difficulty:** Easy

---

## Challenge

The server accepts JWTs with multiple algorithms. Exploit this to gain admin access.

**Endpoints:**
- `/no-way-jose/create_session/<username>/` - Create a session
- `/no-way-jose/authorise/<token>/` - Authorize with a token

---

## Vulnerability: Algorithm "none"

The JWT specification includes an `alg: "none"` option for unsigned tokens. This was intended for situations where the token has already been verified by other means. However, if a server accepts `alg: "none"`, attackers can forge arbitrary tokens without knowing the secret key.

Looking at the source code, the server checks the algorithm and if it's "none", it decodes without signature verification.

---

## Exploit

Create a JWT with `alg: "none"` and `admin: true`:

```python
import base64
import json
import requests

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# Craft token with alg=none
header = {"typ": "JWT", "alg": "none"}
payload = {"admin": True}

header_b64 = b64url_encode(json.dumps(header))
payload_b64 = b64url_encode(json.dumps(payload))

# Empty signature (just a trailing dot)
token = f"{header_b64}.{payload_b64}."

# Submit to get flag
url = f"https://web.cryptohack.org/no-way-jose/authorise/{token}/"
response = requests.get(url)
print(response.json())
```

---

## The Cryptographic Doom Principle

This attack relates to Moxie Marlinspike's principle:

> "If you have to perform any cryptographic operation before verifying the MAC on a message you've received, it will somehow inevitably lead to doom."

The server processes the untrusted `alg` field *before* verifying the token, allowing attackers to dictate how (or whether) verification occurs.

---

## Mitigation

**Never accept `alg: "none"` in production.** Explicitly specify allowed algorithms:

```python
# SECURE
decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

# INSECURE
decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"])
```
