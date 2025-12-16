# HexTree.io Lab Challenges

**Category:** Web Security Labs
**Challenges:** 1

---

## Challenges

| # | Challenge | Vulnerabilities | Difficulty |
|---|-----------|-----------------|------------|
| 1 | [My Movie List](moviedb/) | NoSQL injection, JWT bypass, BOLA | Medium |

---

## My Movie List

A movie database application with multiple security vulnerabilities:

1. **Hidden Test Route** - Debug route exposed in production bundle
2. **Unauthenticated Endpoint** - Backend flag endpoint without auth
3. **BOLA** - Client-side genre restrictions bypass
4. **NoSQL Injection** - MongoDB operator injection in query params
5. **JWT alg=none** - Signature verification bypass for privilege escalation

---

## Key Patterns

- Trust-in-client antipatterns
- Insufficient input validation
- Insecure JWT handling
- Residual debug surfaces in production
