# Oh SNAP (120 pts)

**Category:** AES — Stream Ciphers
**Difficulty:** Hard

---

## Challenge

Attack WEP encryption (the old WiFi security protocol).

---

## Vulnerability

WEP used RC4 with short IVs (24 bits) and weak key scheduling. The combination enables practical key recovery.

**Key insight:** RC4's weak key setup with WEP's key||IV concatenation creates biases in the first keystream bytes that leak key information.

---

## Solution

```python
def wep_attack(packets):
    """FMS/KoreK/PTW attack on WEP"""
    # WEP key schedule: RC4(IV || WEP_key)
    # 24-bit IV = only 16M possibilities = guaranteed reuse

    # FMS attack exploits RC4 key scheduling:
    # - Certain "weak IVs" leak key bytes
    # - ~9000 weak IVs needed for 40-bit key
    # - ~500,000 packets needed for 104-bit key

    # PTW attack (2007):
    # - Uses all packets, not just weak IVs
    # - ~40,000 packets sufficient
    # - Few minutes to crack WEP in practice

    # Collect IVs and corresponding first keystream bytes
    # Statistical analysis reveals key bytes
    pass
```

---

## Key Takeaway

**WEP is completely broken.** Design flaws:
- 24-bit IV = guaranteed collision in ~5000 packets
- Key||IV concatenation exposes key to related-key attacks
- CRC-32 integrity check is malleable (not cryptographic)
- No key derivation function

WEP was replaced by WPA, then WPA2 (AES-CCMP), now WPA3 (SAE+AES-GCM).

