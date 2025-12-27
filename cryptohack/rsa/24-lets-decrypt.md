# Let's Decrypt (80 pts)

**Category:** RSA — Signatures Part 1
**Difficulty:** Medium

---

## Challenge

A domain ownership verification server that validates RSA signatures. The server provides its signature over a fixed message and asks you to prove ownership by presenting a valid signature for a message claiming you own CryptoHack.org.

---

## Vulnerability

The verification logic accepts user-controlled public key parameters (n and e) when checking the signature. This allows an attacker to craft n and e such that the server's original signature validates for any chosen message.

**Key insight:** The server computes `pow(SIGNATURE, e, n)` using attacker-supplied n and e. By choosing e = 1 and n = SIGNATURE - digest, we make the verification pass for our forged message.

---

## Solution

```python
from pkcs1 import emsa_pkcs1_v15
from Crypto.Util.number import bytes_to_long

# Get the server's signature
signature = get_signature_from_server()

# Our forged message
msg = "I am Mallory and I own CryptoHack.org"
digest = bytes_to_long(emsa_pkcs1_v15.encode(msg.encode(), 256))

# Craft n such that: SIGNATURE mod n = digest
# With e = 1: SIGNATURE^1 mod n = digest
# This requires: n | (SIGNATURE - digest)
n = signature - digest  # simplest choice when signature > digest

# Verify: signature % n == digest
assert signature % n == digest

# Submit with e = 1
verify_with_server(msg, n=n, e=1)
```

---

## Key Takeaway

**Never let users control key parameters during verification.** The vulnerability here is a failure of key binding—the signature is valid under the server's key, but verification accepts arbitrary user-supplied keys. Secure systems must:
- Pin the verification key during protocol setup
- Bind signatures to specific public keys
- Never accept user-supplied moduli for signature verification

This attack is related to key substitution attacks in digital signatures.

