# Token Appreciation (5 pts)

**Category:** JSON Web Tokens
**Difficulty:** Starter

---

## Challenge

JWT tokens are encoded, not encrypted. The flag is hidden inside a JWT token provided by the challenge.

---

## Solution

JWTs consist of three base64url-encoded parts separated by dots:
1. **Header** - Algorithm and token type
2. **Payload** - Claims (the actual data)
3. **Signature** - Verification hash

Since JWTs are merely *encoded* (not encrypted), anyone can decode the payload:

```python
import base64
import json

jwt = "<token from challenge>"

# Extract payload (second part)
payload_b64 = jwt.split('.')[1]
payload_b64 += '=' * (4 - len(payload_b64) % 4)  # Add padding
payload = json.loads(base64.urlsafe_b64decode(payload_b64))

print(payload)
# The flag will be in the decoded payload
```

---

## Key Takeaway

**JWTs provide integrity (via signature), not confidentiality.** Never store sensitive information in JWT payloads unless you also encrypt the token (JWE). The signature only prevents tampering—it doesn't hide the contents.
