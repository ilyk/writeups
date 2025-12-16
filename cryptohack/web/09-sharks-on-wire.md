# Sharks on the Wire (10 pts)

**Category:** TLS Part 1
**Difficulty:** Easy

---

## Challenge

Given a PCAP file (`cryptohack.org.pcapng`), count how many packets were received from the cryptohack.org server.

---

## Solution

First, identify which IP address corresponds to cryptohack.org by examining the SNI (Server Name Indication) in TLS ClientHello messages:

```bash
tshark -r cryptohack.org.pcapng -Y "tls.handshake.extensions_server_name" \
    -T fields -e ip.dst -e tls.handshake.extensions_server_name | sort -u
```

This reveals the destination IP associated with the "cryptohack.org" SNI.

Once you know the server's IP, count packets *from* that IP (packets received by the client):

```bash
tshark -r cryptohack.org.pcapng -Y "ip.src==<server_ip>" | wc -l
```

Alternatively, count packets to/from specific IPs to identify the main server:

```bash
tshark -r cryptohack.org.pcapng -T fields -e ip.src | sort | uniq -c | sort -rn
```

---

## Key Takeaway

**SNI reveals the intended server hostname in plaintext** during the TLS handshake (before encryption begins). This is why Encrypted Client Hello (ECH) was developed for TLS 1.3—to protect this metadata from passive observers. PCAP analysis with tshark is essential for network forensics.
