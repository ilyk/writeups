# Vote for Pedro (150 pts)

**Category:** RSA — Signatures Part 2
**Difficulty:** Hard

---

## Challenge

An election server that verifies votes using RSA signatures with e=3. Valid votes are extracted from signatures by parsing the decrypted message at null byte boundaries: `verified_vote.split(b'\x00')[-1]`.

---

## Vulnerability

The server uses RSA signature verification with e=3 without proper padding. The message parsing logic takes everything after the last null byte, allowing signature forgery if we can craft a value x such that x³ ends with `\x00` followed by our target message.

**Key insight:** Since e=3 is small, we can compute x = ∛k (mod 2^b) where k is our target message bytes and b is chosen so that x³ < N. This ensures no modular reduction occurs during verification.

---

## Solution

Find x such that x³ ends with the bytes `\x00VOTE FOR PEDRO`:

```python
# Target: x³ must end with \x00 || "VOTE FOR PEDRO"
target = b"VOTE FOR PEDRO"
k = int.from_bytes(target, 'big')

# Find cube root modulo 2^120 (enough bits for our message)
# Use Hensel lifting or precompute
x = 855520592299350692515886317752220783

# Verify: x³ ends with our target
x_cubed = x ** 3
x_cubed_bytes = x_cubed.to_bytes((x_cubed.bit_length() + 7) // 8, 'big')
assert x_cubed_bytes.split(b'\x00')[-1] == b'VOTE FOR PEDRO'

# Submit x as the signature
send_vote(hex(x))
```

The cube root can be computed iteratively using Hensel's lemma to lift solutions modulo increasing powers of 2.

---

## Key Takeaway

**RSA with small exponents requires proper padding.** Without PKCS#1 padding or similar schemes:
- Attackers can forge signatures for messages that fit within the cube root bound
- The null-byte parsing creates an exploitable attack surface
- PKCS#1 v1.5 prevents this by requiring specific byte structure that can't be easily forged

This attack exploits the combination of unpadded RSA with e=3 and weak message parsing.
