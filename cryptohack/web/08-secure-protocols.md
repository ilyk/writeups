# Secure Protocols (5 pts)

**Category:** TLS Part 1
**Difficulty:** Starter

---

## Challenge

Identify the Certificate Authority (CA) that issued the TLS certificate for tls1.cryptohack.org.

---

## Solution

Use OpenSSL's `s_client` command to connect to the server and inspect the certificate:

```bash
echo | openssl s_client -connect tls1.cryptohack.org:443 2>/dev/null | openssl x509 -noout -issuer
```

This command:
1. Connects to the TLS server
2. Retrieves the certificate
3. Extracts the issuer field (the CA that signed the certificate)

The output shows the CA name in the `CN` (Common Name) field of the issuer.

---

## Key Takeaway

**TLS certificates form a chain of trust.** Each certificate is signed by a CA, which is either a trusted root CA or an intermediate CA that chains back to a root. The issuer field identifies who vouched for the certificate's authenticity.
