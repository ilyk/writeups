# Static Client 2 (120 pts)

**Category:** Diffie-Hellman — Group Theory
**Difficulty:** Hard

---

## Challenge

Similar to Static Client, but with better parameter validation. The prime has a special structure that enables attack.

---

## Vulnerability

The prime `p` is chosen such that `p-1` is **smooth** (has only small prime factors). This enables the **Pohlig-Hellman algorithm** to solve discrete log efficiently.

**Smooth order example:**
```
p - 1 = 2^4 × 3^2 × 5 × 7 × 11 × 13 × ...
```

Instead of solving DLP in a group of order p-1 (hard), we solve it in small subgroups and combine with CRT.

---

## Attack: Pohlig-Hellman

Given A = g^a mod p, to find a:

1. **Factor** p-1 into prime powers: p-1 = q₁^e₁ × q₂^e₂ × ...

2. **For each small prime power qᵢ^eᵢ:**
   - Compute gᵢ = g^((p-1)/qᵢ^eᵢ) (generator of subgroup)
   - Compute Aᵢ = A^((p-1)/qᵢ^eᵢ)
   - Solve discrete log in small subgroup: aᵢ = log_{gᵢ}(Aᵢ)

3. **Combine** using Chinese Remainder Theorem:
   - a ≡ a₁ (mod q₁^e₁)
   - a ≡ a₂ (mod q₂^e₂)
   - ...

---

## Solution

```python
from sympy.ntheory import factorint, discrete_log
from sympy.ntheory.modular import crt

def pohlig_hellman(g, A, p):
    """Solve g^a = A mod p when p-1 is smooth"""
    order = p - 1
    factors = factorint(order)

    residues = []
    moduli = []

    for q, e in factors.items():
        q_e = q ** e
        # Project to subgroup of order q^e
        g_sub = pow(g, order // q_e, p)
        A_sub = pow(A, order // q_e, p)

        # Solve DLP in small subgroup
        a_sub = discrete_log(p, A_sub, g_sub)

        residues.append(a_sub)
        moduli.append(q_e)

    # Combine with CRT
    a, _ = crt(moduli, residues)
    return a

# Attack
a = pohlig_hellman(g, A, p)
shared_secret = pow(B, a, p)
```

---

## Key Takeaway

**The security of DH depends on p-1 having a large prime factor.** Safe primes (p = 2q + 1, q prime) guarantee this. Always verify:
- p is prime
- (p-1)/2 is prime (safe prime)
- Or use elliptic curves (no smooth order issues)

Pohlig-Hellman reduces DLP complexity from O(√n) to O(√q) where q is the largest prime factor.
