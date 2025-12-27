# Pad Thai (80 pts)

**Category:** AES — Padding Attacks
**Difficulty:** Medium

---

## Challenge

Exploit a padding oracle to decrypt CBC ciphertext.

---

## Vulnerability

If a server reveals whether decrypted ciphertext has valid padding, an attacker can decrypt any ciphertext without the key.

**Key insight:** By manipulating the second-to-last ciphertext block, we can brute-force the last plaintext block one byte at a time based on padding validity responses.

---

## Solution

```python
def padding_oracle_attack(ciphertext, oracle):
    """Decrypt CBC ciphertext using padding oracle"""
    block_size = 16
    plaintext = b""

    for block_num in range(len(ciphertext) // block_size - 1, 0, -1):
        block = ciphertext[block_num * block_size:(block_num + 1) * block_size]
        prev_block = bytearray(ciphertext[(block_num - 1) * block_size:block_num * block_size])
        intermediate = [0] * block_size

        for byte_pos in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_pos

            # Set already-known bytes to produce correct padding
            for i in range(byte_pos + 1, block_size):
                prev_block[i] = intermediate[i] ^ padding_value

            # Brute force current byte
            for guess in range(256):
                prev_block[byte_pos] = guess
                if oracle(bytes(prev_block) + block):
                    intermediate[byte_pos] = guess ^ padding_value
                    break

        # Recover plaintext from intermediate state
        orig_prev = ciphertext[(block_num - 1) * block_size:block_num * block_size]
        plaintext = bytes(a ^ b for a, b in zip(intermediate, orig_prev)) + plaintext

    return plaintext
```

---

## Key Takeaway

**Padding oracles decrypt without the key.** Attack requires:
- CBC mode with PKCS#7 padding
- Distinguishable padding error response
- ~256 × 16 = 4096 queries per block

Mitigation: Use authenticated encryption (GCM), or ensure errors are indistinguishable (constant-time, same error message).

