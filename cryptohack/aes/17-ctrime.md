# CTRIME (70 pts)

**Category:** AES — Stream Ciphers
**Difficulty:** Medium

---

## Challenge

Exploit compression before encryption to leak secret data (CRIME attack variant).

---

## Vulnerability

When data is compressed before encryption, the ciphertext length reveals information about the plaintext if attacker controls part of the input.

**Key insight:** Compression reduces size when there are repeated patterns. If `secret` appears in both attacker input and actual secret, compression is better, resulting in shorter ciphertext.

---

## Solution

```python
import string

def crime_attack(oracle):
    """Recover secret byte-by-byte via compression oracle"""
    known = ""
    charset = string.printable

    while True:
        baseline_len = None
        found = False

        for c in charset:
            guess = known + c
            # Oracle compresses and encrypts: compress(user_input || secret)
            length = len(oracle(guess))

            if baseline_len is None:
                baseline_len = length

            if length < baseline_len:
                # Shorter = better compression = character matches secret
                known += c
                found = True
                break

        if not found:
            break

    return known
```

---

## Key Takeaway

**Never compress then encrypt with attacker-controlled data.** The CRIME/BREACH attacks exploited this in TLS:
- Attacker injects guesses into requests
- Observes compressed+encrypted response size
- Byte-by-byte secret recovery

Mitigations: Don't compress secrets, add random padding, separate secret and attacker-controlled data.

