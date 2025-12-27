# Prime and Prejudice (200 pts)

**Category:** Mathematics — Primes
**Difficulty:** Hard

---

## Challenge

Interactive server tests if our submitted number is prime using Miller-Rabin with fixed bases. We must submit a composite that passes the test.

---

## Vulnerability

Miller-Rabin primality testing can be fooled by **strong pseudoprimes** - composites that pass the test for specific bases.

**Key insight:** The Arnault method (from the 2018 paper "Prime and Prejudice: Primality Testing Under Adversarial Conditions") constructs n = p₁ × p₂ × p₃ that passes Miller-Rabin for all prime bases < 64.

The trick to get the full flag: send the pseudoprime with one of its prime factors as the "base" parameter!

---

## Solution

```python
from Crypto.Util.number import isPrime, inverse, GCD
import itertools

def generate_pseudoprime():
    """Generate strong pseudoprime using Arnault's method"""
    primes = sieve_up_to(64)  # bases to fool
    h = 3  # number of factors
    ks = [1, 998244353, 233]  # magic constants

    # Build constraint sets using Legendre symbols
    # ... (see full implementation)

    # Search for valid candidate
    for candidate in search_space:
        if isPrime(candidate):
            n = candidate
            factors = [candidate]
            for k in ks[1:]:
                factor = k * (candidate - 1) + 1
                factors.append(factor)
                n *= factor

            if passes_miller_rabin(n, 64) and 700 <= n.bit_length() <= 900:
                return n, factors

    return None, None

# Generate pseudoprime
psp, factors = generate_pseudoprime()

# Connect and send with factor as base
r = remote('socket.cryptohack.org', 13385)
r.recvline()

smallest_factor = min(factors)
r.sendline(json.dumps({
    "prime": psp,
    "base": smallest_factor
}).encode())

# Reveals full flag!
print(r.recvline().decode())
```

---

## Key Takeaway

**Deterministic primality tests with fixed bases are vulnerable.** The Miller-Rabin test is probabilistic - it can be fooled:

1. **Strong pseudoprimes exist** for any fixed set of bases
2. **Arnault's construction** systematically generates them using:
   - Legendre symbol constraints
   - Chinese Remainder Theorem
   - Careful prime selection

**Defense:** Use either:
- Random bases (harder to predict what to fool)
- Deterministic tests like AKS
- Multiple rounds with different base sets

The flag references François Arnault who pioneered this research, showing that "primality testing under adversarial conditions" is fundamentally different from standard probabilistic testing.

**Reference:** [Prime and Prejudice (ePrint 2018/749)](https://eprint.iacr.org/2018/749.pdf)
