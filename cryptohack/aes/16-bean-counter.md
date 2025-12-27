# Bean Counter (60 pts)

**Category:** AES — Stream Ciphers
**Difficulty:** Medium

---

## Challenge

A CTR mode implementation uses a predictable counter. Exploit it to decrypt.

---

## Vulnerability

CTR mode requires unique counter values for each block ever encrypted under the same key. Predictable or reused counters enable keystream recovery.

**Key insight:** If counter(message1, block_i) = counter(message2, block_j), then keystream blocks are identical, enabling XOR-based attacks.

---

## Solution

```python
def ctr_attack(oracle, known_plaintext, target_ciphertext):
    """Exploit predictable CTR counter"""
    # CTR: C[i] = P[i] ⊕ E(counter + i)

    # If we know a plaintext-ciphertext pair, we can recover keystream:
    # keystream[i] = P[i] ⊕ C[i]

    # If same counter is reused:
    # P_unknown = C_target ⊕ keystream[i]

    # Get keystream from known pair
    known_ct = oracle(known_plaintext)
    keystream = bytes(a ^ b for a, b in zip(known_plaintext, known_ct))

    # Decrypt target
    plaintext = bytes(a ^ b for a, b in zip(target_ciphertext, keystream))
    return plaintext
```

---

## Key Takeaway

**CTR counters must never repeat under the same key.** Common mistakes:
- Starting counter at 0 for each message
- 32-bit counter overflow
- Predictable nonce generation

Safe CTR usage: random 96-bit nonce + 32-bit counter (limits message to 2^32 blocks ≈ 64GB).

