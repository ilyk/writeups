# Logon Zero (80 pts)

**Category:** AES — Stream Ciphers
**Difficulty:** Medium

---

## Challenge

Exploit the Zerologon vulnerability (CVE-2020-1472) in Netlogon's AES-CFB8 implementation.

---

## Vulnerability

Windows Netlogon used AES-CFB8 with a static IV of all zeros. In CFB8, an all-zero IV with all-zero plaintext produces all-zero ciphertext with probability 1/256.

**Key insight:** By repeatedly trying authentication with all-zero client credential, attackers can authenticate with probability 1/256 per attempt—bypassing authentication entirely.

---

## Solution

```python
def zerologon_attack():
    """Zerologon: AES-CFB8 with IV=0 vulnerability"""
    # AES-CFB8 processes 1 byte at a time:
    # C[0] = P[0] ⊕ E(IV)[0]
    # C[1] = P[1] ⊕ E(IV || C[0])[0]
    # ...

    # If IV = 0x00...00 and E(0)[0] = 0x00 (1/256 chance):
    # C[0] = P[0] ⊕ 0 = P[0]
    # If P[0] = 0: C[0] = 0, and the pattern continues

    # With all-zero plaintext and lucky key:
    # All-zero input → all-zero output

    # Attack: Try authentication ~256 times with zero credentials
    for attempt in range(256):
        # Send authentication request with:
        # - Client credential: 00 00 00 00 00 00 00 00
        # - Timestamp: 00 00 00 00 00 00 00 00
        if try_auth(b"\x00" * 8):
            print(f"Success after {attempt} attempts!")
            break
```

---

## Key Takeaway

**CFB8 with zero IV is catastrophically weak.** Zerologon impact:
- Unauthenticated domain admin access
- One of the most severe Windows vulnerabilities
- CVSS 10.0

Lessons: Never use static IVs, prefer standard modes (GCM), test crypto implementations thoroughly.

