# Decrypting TLS 1.3 (35 pts)

**Category:** TLS Part 1
**Difficulty:** Medium

---

## Challenge

Decrypt TLS 1.3 traffic using a keylog file containing the session secrets.

**Files provided:**
- `tls3.cryptohack.org.pcapng` - Captured TLS 1.3 traffic
- `keylogfile.txt` - NSS key log file with session secrets

---

## Solution

TLS 1.3 mandates ephemeral key exchange, so the server's private key alone cannot decrypt traffic. However, if the session secrets were logged (e.g., via `SSLKEYLOGFILE`), decryption is possible.

Use tshark with the keylog file:

```bash
tshark -r tls3.cryptohack.org.pcapng \
    -o "tls.keylog_file:keylogfile.txt" \
    -Y http2 \
    -T fields -e http2.data.data 2>/dev/null | xxd -r -p
```

### NSS Key Log Format

The keylog file contains lines like:
```
CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>
SERVER_TRAFFIC_SECRET_0 <client_random> <secret>
```

Each line maps a client random (from ClientHello) to its derived secrets.

---

## Key Takeaway

**TLS 1.3 always provides forward secrecy.** Unlike TLS 1.2 with RSA key exchange, you cannot decrypt TLS 1.3 traffic with just the server's private key. Decryption requires the ephemeral session secrets—typically only available if the application exports them via `SSLKEYLOGFILE`. This environment variable is supported by browsers and many TLS libraries for debugging purposes.
