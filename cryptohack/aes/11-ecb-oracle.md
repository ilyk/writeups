# ECB Oracle (60 pts)

**Category:** AES — Block Ciphers 1
**Difficulty:** Medium

---

## Challenge

An ECB encryption oracle appends a secret to your input before encrypting. Extract the secret byte-by-byte.

---

## Vulnerability

ECB's deterministic encryption enables byte-at-a-time decryption when an attacker controls prefix data.

**Key insight:** By controlling block alignment, we can brute-force one byte at a time by comparing ciphertext blocks.

---

## Solution

```python
def ecb_oracle(plaintext):
    """Server encrypts: AES-ECB(plaintext || secret)"""
    # Returns ciphertext
    pass

def attack():
    secret = b""
    block_size = 16

    for i in range(32):  # Assume secret < 32 bytes
        # Pad so next unknown byte is at block boundary
        padding = b"A" * (block_size - 1 - (len(secret) % block_size))

        # Get target ciphertext
        target = ecb_oracle(padding)
        target_block = target[:block_size * ((len(padding) + len(secret)) // block_size + 1)]

        # Brute force the next byte
        for byte in range(256):
            guess = padding + secret + bytes([byte])
            result = ecb_oracle(guess)
            if result[:len(target_block)] == target_block:
                secret += bytes([byte])
                break

    return secret
```

---

## Key Takeaway

**ECB oracles leak secrets byte-by-byte.** This attack requires:
- Attacker-controlled prefix
- Deterministic encryption (no random IV)
- Ability to observe ciphertext

This is why ECB is never used in practice—even with authenticated encryption, the pattern leakage is dangerous.

