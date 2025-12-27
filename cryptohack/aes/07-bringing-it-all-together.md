# Bringing It All Together (50 pts)

**Category:** AES — How AES Works
**Difficulty:** Easy

---

## Challenge

Implement a complete AES decryption to recover a message encrypted with a known key.

---

## Vulnerability

Understanding the full AES structure allows implementing both encryption and decryption, essential for cryptanalysis work.

**Key insight:** Decryption applies inverse operations in reverse order: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns.

---

## Solution

```python
from Crypto.Cipher import AES

def decrypt_aes(ciphertext, key):
    """Decrypt using PyCryptodome"""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

# Manual implementation structure:
def aes_decrypt(ciphertext, key):
    state = bytes_to_matrix(ciphertext)
    round_keys = expand_key(key)

    # Initial round
    add_round_key(state, round_keys[10])

    # 9 main rounds (in reverse)
    for i in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[i])
        inv_mix_columns(state)

    # Final round
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    return matrix_to_bytes(state)
```

---

## Key Takeaway

**AES decryption is not just encryption in reverse.** The order of operations changes:
- Encryption: SubBytes → ShiftRows → MixColumns → AddRoundKey
- Decryption: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns
- AddRoundKey is its own inverse (XOR)
- Last encryption round skips MixColumns, so first decryption round skips InvMixColumns

