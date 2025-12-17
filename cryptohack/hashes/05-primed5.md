# PriMeD5 (100 pts)

**Category:** Hash Functions — Collisions
**Difficulty:** Hard

---

## Challenge

Find two values x1 and x2 such that:
- MD5(x1) = MD5(x2)
- is_prime(x1) = True
- is_prime(x2) = False

---

## Vulnerability

MD5 collision generation produces pairs of bytestrings that differ in specific bit positions. When interpreted as integers, one may be prime while the other is composite.

**Attack approach:**
1. Generate many MD5 collision pairs
2. Interpret collision blocks as large integers
3. Test primality of both integers
4. Find pair where exactly one is prime

---

## Solution

```python
import subprocess
from hashlib import md5

def is_prime_miller_rabin(n, rounds=40):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    import random
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_collision():
    """Use fastcoll to generate MD5 collision"""
    subprocess.run(['fastcoll', '-o', 'c1.bin', 'c2.bin'], check=True)
    with open('c1.bin', 'rb') as f:
        c1 = f.read()
    with open('c2.bin', 'rb') as f:
        c2 = f.read()
    return c1, c2

# Search for prime/composite collision pair
while True:
    c1, c2 = generate_collision()

    # Interpret as integers (big-endian)
    x1 = int.from_bytes(c1, 'big')
    x2 = int.from_bytes(c2, 'big')

    p1 = is_prime_miller_rabin(x1)
    p2 = is_prime_miller_rabin(x2)

    if p1 != p2:
        prime_one = x1 if p1 else x2
        composite_one = x2 if p1 else x1
        print(f"Found! Prime: {prime_one.bit_length()} bits")
        break
```

---

## Key Takeaway

**Collision attacks can have real-world consequences beyond simple equality.** Here, the collision enables bypassing primality checks. In practice, similar attacks could:
- Create colliding certificates (one valid, one malicious)
- Bypass integrity checks on executables
- Forge documents with different semantic meaning

The combination of MD5's broken collision resistance with domain-specific checks creates exploitable vulnerabilities.
