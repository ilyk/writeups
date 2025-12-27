# Cofactor Cofantasy (150 pts)

**Category:** Mathematics — Brainteasers Part 2
**Difficulty:** Hard

---

## Challenge

Interactive challenge where we query for flag bits. For each bit:
- bit = 1: server returns g^random (element of specific subgroup)
- bit = 0: server returns random element

Given: N = p*q (safe primes), φ(N), and generator g with order φ/32768.

---

## Vulnerability

Subgroup membership attack using the element order structure.

**Key insight:** g has order φ/32768, so g^r always satisfies (g^r)^(φ/32768) = 1. Random elements typically don't lie in this subgroup.

However, testing with φ/32768 is too coarse - all samples pass. The discriminator is φ/65536:
- For bit=1: g^r passes φ/65536 test ~50% of the time (when r is even)
- For bit=0: random elements rarely pass φ/65536 test

**Detection rule:** If ANY sample passes φ/65536 test → bit = 1. If NONE pass → bit = 0.

---

## Solution

```python
from pwn import remote
import json

N = ...   # from challenge
phi = ... # from challenge
order = phi // 65536  # discriminator order

r = remote('socket.cryptohack.org', 13398)
r.recvline()

flag_bits = []
for bit_idx in range(400):
    count = 0
    for _ in range(10):  # multiple samples
        r.sendline(json.dumps({"option": "get_bit", "i": bit_idx}).encode())
        resp = json.loads(r.recvline().decode())
        v = int(resp['bit'], 16)

        if pow(v, order, N) == 1:
            count += 1

    # Any sample in subgroup → bit is 1
    flag_bits.append(1 if count > 0 else 0)

    # Check for end of flag
    if (bit_idx + 1) % 8 == 0:
        byte_bits = flag_bits[-8:]
        # Bits are LSB first!
        char_val = sum(b * (2**i) for i, b in enumerate(byte_bits))
        if char_val == ord('}'):
            break

# Reconstruct flag (LSB first within each byte)
flag = ''.join(chr(sum(flag_bits[i+j]*(2**j) for j in range(8)))
               for i in range(0, len(flag_bits), 8))
print(flag)
```

---

## Key Takeaway

**Subgroup structure leaks information.** When elements are constrained to a subgroup:

1. Test membership using v^(group_order) = 1
2. Choose the test order carefully - too large captures everything, too small misses patterns
3. The exact order of g matters: here φ/32768, but φ/65536 provides better discrimination

This attack is related to:
- Invalid curve attacks on ECDH
- Small subgroup attacks on Diffie-Hellman
- Pohlig-Hellman algorithm exploiting smooth group orders
