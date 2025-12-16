# JWT Secrets (25 pts)

**Category:** JSON Web Tokens
**Difficulty:** Easy

---

## Challenge

The server uses HS256 to sign JWTs. The challenge hint mentions that the developer used a key from a library's example code.

**Endpoints:**
- `/jwt-secrets/create_session/<username>/` - Create a session
- `/jwt-secrets/authorise/<token>/` - Authorize with a token

---

## Vulnerability: Weak Secret Key

The source code contains a telling comment:

```python
SECRET_KEY = ?  # TODO: PyJWT readme key, change later
```

Checking the [PyJWT documentation](https://pyjwt.readthedocs.io/), the example code uses:

```python
encoded = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")
```

The developer likely copy-pasted this example, leaving `"secret"` as the actual key.

---

## Exploit

Forge an admin token using the guessed secret:

```python
import jwt
import requests

# Forge admin token with the default PyJWT example key
token = jwt.encode({"admin": True}, "secret", algorithm="HS256")

url = f"https://web.cryptohack.org/jwt-secrets/authorise/{token}/"
response = requests.get(url)
print(response.json())
```

---

## Real-World Impact

This is a common vulnerability. A 2017 study found thousands of JWTs in the wild using secrets like:
- `secret`
- `password`
- `123456`
- Company names
- Default framework values

Tools like `jwt_tool` and `hashcat` can crack weak JWT secrets efficiently.

---

## Mitigation

Generate cryptographically secure keys:

```python
import secrets

# Generate a 256-bit (32 byte) random key
SECRET_KEY = secrets.token_hex(32)
```

For HS256, NIST recommends keys of at least 256 bits (32 bytes).
