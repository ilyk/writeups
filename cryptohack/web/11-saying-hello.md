# Saying Hello (20 pts)

**Category:** TLS Part 1
**Difficulty:** Easy

---

## Challenge

Connect to tls1.cryptohack.org using TLS 1.2 specifically and determine which cipher suite is negotiated.

---

## Solution

Force a TLS 1.2 connection using OpenSSL's `-tls1_2` flag:

```bash
echo | openssl s_client -connect tls1.cryptohack.org:443 -tls1_2 2>/dev/null | grep "Cipher is"
```

The output shows the negotiated cipher suite in OpenSSL's naming convention.

You can also see more details about the connection:

```bash
openssl s_client -connect tls1.cryptohack.org:443 -tls1_2 </dev/null 2>/dev/null
```

Look for the "Cipher" line in the output which shows the full cipher suite name.

### Cipher Suite Components
A typical TLS 1.2 cipher suite name like `ECDHE-RSA-AES256-GCM-SHA384` indicates:
- **ECDHE**: Key exchange (Elliptic Curve Diffie-Hellman Ephemeral)
- **RSA**: Authentication method
- **AES256-GCM**: Bulk encryption (256-bit AES in GCM mode)
- **SHA384**: Hash function for PRF

---

## Key Takeaway

**Different TLS versions support different cipher suites.** TLS 1.3 dramatically simplified the cipher suite list, removing legacy algorithms. When testing server configurations, always check which versions and suites are supported—some servers may negotiate weaker options for backward compatibility.
