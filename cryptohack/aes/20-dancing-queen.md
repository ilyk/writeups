# Dancing Queen (120 pts)

**Category:** AES — Stream Ciphers
**Difficulty:** Hard

---

## Challenge

Exploit a weakness in a Salsa20/ChaCha variant implementation.

---

## Vulnerability

Salsa20 and ChaCha use quarter-round functions that mix 32-bit words. Implementation errors or reduced rounds can break the cipher.

**Key insight:** The mixing functions must be applied correctly for security. Skipping or incorrectly implementing rounds allows differential attacks.

---

## Solution

```python
def analyze_quarterround(a, b, c, d):
    """ChaCha quarter round analysis"""
    # Standard quarter round:
    # a += b; d ^= a; d <<<= 16;
    # c += d; b ^= c; b <<<= 12;
    # a += b; d ^= a; d <<<= 8;
    # c += d; b ^= c; b <<<= 7;

    # If any operation is missing or incorrect:
    # - Differential patterns propagate predictably
    # - Statistical biases appear in output
    # - Keystream becomes distinguishable from random

# Specific attack depends on the implementation flaw...
```

---

## Key Takeaway

**Stream cipher implementations must be exact.** Common vulnerabilities:
- Reduced rounds (ChaCha20 has 20 rounds for a reason)
- Incorrect rotation amounts
- Missing operations in quarter rounds
- Nonce reuse (same as keystream reuse)

ChaCha20 and Salsa20 are well-designed but implementation matters.

