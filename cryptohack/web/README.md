# CryptoHack Web Challenges

Writeups for the CryptoHack Web category challenges.

## Progress

### JWT Section (7/7 - 235 pts)

| # | Challenge | Points | Status |
|---|-----------|--------|--------|
| 1 | Token Appreciation | 5 | Solved |
| 2 | JWT Sessions | 10 | Solved |
| 3 | No Way JOSE | 20 | Solved |
| 4 | JWT Secrets | 25 | Solved |
| 5 | RSA or HMAC? | 35 | Solved |
| 6 | JSON in JSON | 40 | Solved |
| 7 | RSA or HMAC? Part 2 | 100 | Solved |

### TLS Part 1 (7/7 - 155 pts)

| # | Challenge | Points | Status |
|---|-----------|--------|--------|
| 8 | Secure Protocols | 5 | Solved |
| 9 | Sharks on the Wire | 10 | Solved |
| 10 | TLS Handshake | 15 | Solved |
| 11 | Saying Hello | 20 | Solved |
| 12 | Decrypting TLS 1.2 | 30 | Solved |
| 13 | Decrypting TLS 1.3 | 35 | Solved |
| 14 | Authenticated Handshake | 40 | Solved |

### Cloud (2/3 - 220 pts)

| # | Challenge | Points | Status |
|---|-----------|--------|--------|
| 15 | Megalomaniac 1 | 100 | Solved |
| 16 | Megalomaniac 2 | 125 | Pending |
| 17 | Megalomaniac 3 | 120 | Solved |

**Total: 16/17 (610 pts)**

---

## Key Learnings

### JWT Attack Surface

| Attack | Vulnerability | Mitigation |
|--------|--------------|------------|
| Decode payload | JWTs are encoded, not encrypted | Don't store secrets in JWTs |
| `alg: none` | Server accepts unsigned tokens | Explicitly whitelist algorithms |
| Weak secret | Guessable/default HMAC key | Use 256+ bit random keys |
| Algorithm confusion | RS256→HS256 with public key | Don't mix symmetric/asymmetric |
| Key recovery | RSA pubkey from signatures | Use key pinning, not just algorithm |
| JSON injection | String concatenation for JSON | Use `json.dumps()` |

### TLS Concepts

| Concept | TLS 1.2 | TLS 1.3 |
|---------|---------|---------|
| Forward Secrecy | Optional (RSA vs ECDHE) | Mandatory (always ephemeral) |
| Decryption with private key | Possible (RSA key exchange) | Not possible |
| Decryption with keylog | Possible | Possible |
| Handshake round-trips | 2 RTT | 1 RTT |
| Cipher suites | Many legacy options | 5 modern suites only |

### TLS 1.3 Key Derivation

```
ClientHello + ServerHello → Early Secret → Handshake Secret → Master Secret
                                ↓
                     [client|server]_handshake_traffic_secret
                                ↓
                        write_key, write_iv, finished_key
```

### Useful Commands

```bash
# Certificate inspection
openssl s_client -connect host:443 2>/dev/null | openssl x509 -noout -issuer

# Force TLS version
openssl s_client -connect host:443 -tls1_2

# PCAP analysis
tshark -r file.pcapng -Y "tls.handshake.type==2" -T fields -e tls.handshake.random

# TLS 1.2 decryption (RSA key exchange)
tshark -r file.pcapng -o "tls.keys_list:,443,http,privkey.pem" -Y http2

# TLS 1.3 decryption (keylog file)
tshark -r file.pcapng -o "tls.keylog_file:keylog.txt" -Y http2
```

---

## References

### JWT
- [JWT.io](https://jwt.io/) - Debugger and library list
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html)
- [Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [rsa_sign2n](https://github.com/silentsignal/rsa_sign2n) - RSA public key recovery from signatures

### TLS
- [The Illustrated TLS 1.3 Connection](https://tls13.xargs.org/) - Visual TLS 1.3 explanation
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) - TLS 1.3 specification
- [Wireshark TLS Decryption](https://wiki.wireshark.org/TLS) - How to decrypt TLS in Wireshark/tshark
