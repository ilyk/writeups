# Roll your Own (125 pts)

**Category:** Mathematics — Brainteasers Part 2
**Difficulty:** Medium

---

## Challenge

Server generates a 512-bit prime q and random secret x. We provide (g, n) such that g^q ≡ 1 (mod n). Server computes h = g^x mod n. We must recover x.

---

## Vulnerability

The p-adic logarithm attack exploits the structure of Z_{q²}*.

**Key insight:** In Z_{q²}*, elements of form (1 + kq) have order dividing q. For g = 1 + q:
```
g^x = (1 + q)^x ≡ 1 + xq (mod q²)  [by binomial expansion]
```

This gives us a **closed-form DLP solution**:
```
x = (h - 1) / q (mod q)
```

---

## Solution

```python
from pwn import remote
import json

r = remote('socket.cryptohack.org', 13403)

# Receive q from server
line = r.recvline().decode()
q = int(line.split('"')[1], 16)

# Use n = q² and g = 1 + q
n = q * q
g = 1 + q  # Element of order q in Z_{q²}*

# Verify: g^q ≡ 1 (mod n)
assert pow(g, q, n) == 1

# Send (g, n) to server
r.sendline(json.dumps({"g": hex(g), "n": hex(n)}).encode())

# Receive h = g^x mod n
resp = r.recvline().decode()
h = int(resp.split('"')[1], 16)

# Solve DLP using p-adic logarithm
# h = (1+q)^x ≡ 1 + xq (mod q²)
# So x = (h - 1) / q mod q
x = ((h - 1) // q) % q

# Send solution
r.sendline(json.dumps({"x": hex(x)}).encode())
print(r.recvall().decode())
```

---

## Key Takeaway

**Prime powers create algebraic structure that breaks DLP.** The p-adic logarithm is related to the Paillier cryptosystem's homomorphic properties:

1. In Z_{p²}*, elements (1 + kp) form a subgroup of order p
2. Exponentiation becomes linear: (1+p)^x ≡ 1 + xp (mod p²)
3. DLP reduces to simple division

This is why Paillier uses (1+n) as the generator - it enables homomorphic addition while making the "discrete log" (plaintext) recoverable with the secret key.
