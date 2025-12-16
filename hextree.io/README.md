# HexTree.io Writeups

**Platform:** [HexTree.io](https://hextree.io/)
**Author:** ilyk
**Date:** September 2025

---

## Overview

Writeups for HexTree.io security challenges focusing on web application vulnerabilities.

**Total Challenges:** 1

---

## Categories

| Category | Challenges | Status |
|----------|------------|--------|
| [Lab](lab/) | 1 | Complete |

---

## Challenge Breakdown

### Lab (1 challenge)
Web application security challenges with real-world vulnerability patterns.

| Challenge | Vulnerabilities |
|-----------|-----------------|
| My Movie List | Hidden routes, NoSQL injection, BOLA, JWT alg=none |

---

## Key Techniques

| Technique | Description |
|-----------|-------------|
| NoSQL Injection | MongoDB operator injection via query params |
| JWT alg=none | Signature verification bypass |
| BOLA | Broken Object Level Authorization |
| Client-side bypass | UI-only access controls |

---

## Tools Used

- **Browser DevTools:** Bundle analysis, network inspection
- **curl/jq:** API testing
- **JavaScript:** JWT forgery, cipher decoding
