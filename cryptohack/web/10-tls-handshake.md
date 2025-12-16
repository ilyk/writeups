# TLS Handshake (15 pts)

**Category:** TLS Part 1
**Difficulty:** Easy

---

## Challenge

Extract the Server Random value from the TLS handshake in the provided PCAP file (`cryptohack.org.pcapng`).

---

## Solution

The Server Random is a 32-byte value sent in the ServerHello message (handshake type 2). Use tshark to extract it:

```bash
tshark -r cryptohack.org.pcapng -Y "tls.handshake.type==2" \
    -T fields -e tls.handshake.random
```

The filter `tls.handshake.type==2` matches ServerHello messages specifically.

### TLS Handshake Types Reference
| Type | Message |
|------|---------|
| 1 | ClientHello |
| 2 | ServerHello |
| 11 | Certificate |
| 12 | ServerKeyExchange |
| 14 | ServerHelloDone |
| 16 | ClientKeyExchange |
| 20 | Finished |

---

## Key Takeaway

**The Server Random is critical for key derivation.** Both Client Random and Server Random contribute entropy to the master secret calculation, preventing replay attacks and ensuring each session has unique keys. The random values are transmitted in plaintext during the handshake.
