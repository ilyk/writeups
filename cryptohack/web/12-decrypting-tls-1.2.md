# Decrypting TLS 1.2 (30 pts)

**Category:** TLS Part 1
**Difficulty:** Medium

---

## Challenge

Given a PCAP file with TLS 1.2 traffic and the server's RSA private key, decrypt the traffic to find the flag.

**Files provided:**
- `tls2.cryptohack.org.pcapng` - Captured TLS traffic
- `privkey.pem` - Server's RSA private key

---

## Solution

TLS 1.2 with RSA key exchange (non-ephemeral) allows decryption if you have the server's private key. This is because the pre-master secret is encrypted directly with the server's RSA public key.

Use tshark with the private key to decrypt:

```bash
tshark -r tls2.cryptohack.org.pcapng \
    -o "tls.keys_list:,443,http,privkey.pem" \
    -Y http2 \
    -T fields -e http2.data.data 2>/dev/null | xxd -r -p
```

**Important syntax notes:**
- The `tls.keys_list` format is `,port,protocol,keyfile` (note the leading comma—no IP address)
- Use `-Y http2` for HTTP/2 traffic (common with TLS)
- Use `http2.data.data` to extract the HTTP/2 payload
- Pipe through `xxd -r -p` to convert hex to ASCII

---

## Key Takeaway

**RSA key exchange lacks forward secrecy.** If the server's private key is compromised, all past recorded traffic can be decrypted. This is why modern TLS configurations prefer ephemeral Diffie-Hellman (ECDHE) key exchange—even if the server key is later compromised, past session keys remain safe because they were never transmitted.
