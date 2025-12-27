# Megalomaniac 3 (120 pts)

**Category:** Web — Cloud (MEGA)
**Difficulty:** Hard

---

## Challenge

Exploit MEGA's lack of integrity checks to substitute encrypted blocks.

---

## Vulnerability

MEGA encrypts files with AES-ECB for key material without authentication. An attacker controlling the encrypted blob can substitute blocks.

**Key insight:** ECB mode encrypts identical blocks identically. By swapping encrypted blocks between known and unknown data, we can substitute known values.

---

## Solution

```python
def mega3_attack(encrypted_blob, known_block, target_position):
    """
    ECB block substitution attack

    MEGA structure:
    - Encrypted file key (32 bytes = 2 AES blocks)
    - Encrypted file data

    Attack:
    1. Upload a file with known content
    2. Observe the encrypted block for that content
    3. Substitute this known block into the target position
    4. Server decrypts to our controlled value
    """
    block_size = 16

    # Extract the encrypted block for known plaintext
    known_encrypted = encrypt_known_plaintext(known_block)

    # Substitute into target blob
    blob = bytearray(encrypted_blob)
    start = target_position * block_size
    blob[start:start + block_size] = known_encrypted

    return bytes(blob)
```

---

## Key Takeaway

**Integrity checks are essential.** Without authentication:
- ECB blocks can be freely rearranged
- Known plaintext enables targeted substitution
- Ciphertext malleability breaks system security

MEGA's vulnerability (discovered 2022) allowed RSA private key recovery through block manipulation. Always use authenticated encryption.

