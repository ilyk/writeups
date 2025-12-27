# Megalomaniac 1 (100 pts)

**Category:** Web — Cloud (MEGA)
**Difficulty:** Hard

---

## Challenge

Exploit a vulnerability in MEGA's RSA-CRT implementation to recover private key material.

---

## Vulnerability

MEGA uses RSA with Chinese Remainder Theorem (CRT) optimization. The server provides an oracle that decrypts and checks if the result is 32 bytes.

**Key insight:** By performing a binary search with carefully crafted ciphertexts, we can determine the private key's relationship to query values, eventually recovering enough information to factor n.

---

## Solution

```python
def mega1_attack(oracle, n, e):
    """
    RSA-CRT binary search attack

    The oracle tells us if decrypt(c) is 32 bytes (256 bits).
    We use this to perform binary search:

    1. Encrypt m * 2^k for increasing k
    2. When decryption no longer fits in 32 bytes, we've found a bound
    3. Binary search refines the boundary
    4. Multiple boundaries reveal information about private key
    """
    # Find where 32-byte boundary lies
    low, high = 0, 2**256

    while high - low > 1:
        mid = (low + high) // 2
        c = pow(mid, e, n)

        if oracle(c):  # Returns True if 32 bytes
            low = mid
        else:
            high = mid

    # The boundary reveals information about d and n's factors
    # Repeated queries from different angles recover p, q
```

---

## Key Takeaway

**Length oracles leak key information.** The attack exploits:
- Deterministic relationship between ciphertext and plaintext length
- Binary search reduces complexity from brute force to logarithmic
- Side-channel through response variation

Mitigations: Constant-time operations, fixed-length outputs, no length-dependent responses.

