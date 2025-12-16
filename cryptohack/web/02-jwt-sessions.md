# JWT Sessions (10 pts)

**Category:** JSON Web Tokens
**Difficulty:** Starter

---

## Challenge

The challenge explains how JWTs differ from traditional session cookies:

> "With session ID cookies, sessions live on the server, but with JWTs, sessions live on the client."

**Question:** What is the name of the HTTP header used by the browser to send JWTs to the server?

---

## Solution

When a client authenticates, the server issues a JWT. On subsequent requests, the client sends this token back to prove identity. The standard HTTP header for this uses the "Bearer" scheme:

```
Authorization: Bearer <token>
```

The answer is the name of this header.

---

## JWT vs Session Cookies

| Aspect | Session Cookies | JWTs |
|--------|-----------------|------|
| **Storage** | Server-side (session store) | Client-side (browser) |
| **Scalability** | Requires shared session store | Stateless, any server can verify |
| **Revocation** | Easy (delete from store) | Hard (token valid until expiry) |
| **Size** | Small (just session ID) | Larger (contains all claims) |
