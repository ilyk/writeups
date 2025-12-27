# Null or Never (100 pts)

**Category:** RSA — Padding
**Difficulty:** Medium

---

## Challenge

RSA encryption with e=3 where the flag is padded to 100 bytes with null bytes before encryption. The padding structure is: `flag || \x00 * (100 - len(flag))`.

---

## Vulnerability

Coppersmith's small roots attack applies when:
1. The exponent e is small (e=3)
2. Part of the message is known or constrained
3. The unknown portion is small enough (< n^(1/e))

With null padding, we know the flag has structure `crypto{...}` and the trailing bytes are zeros. This makes it a "stereotyped message" attack.

---

## Solution

Use SageMath's `small_roots()` for Coppersmith's method with known prefix/suffix:

```sage
# Known structure: crypto{UNKNOWN} + null padding
prefix = b"crypto{"
suffix = b"}"

# Message layout: prefix || unknown || suffix || zeros
# m = A + B*x where:
#   A = contribution from known parts (prefix and suffix)
#   B = positional multiplier for unknown part
#   x = unknown middle section

for unknown_len in range(30, 40):  # Try different lengths
    total_len = 8 + unknown_len  # prefix + unknown + suffix
    padding_len = 100 - total_len

    # Build polynomial coefficients
    prefix_shift = 8 * (unknown_len + 1 + padding_len)
    unknown_shift = 8 * (1 + padding_len)
    suffix_shift = 8 * padding_len

    A = pre_val * 2^prefix_shift + suf_val * 2^suffix_shift
    B = 2^unknown_shift

    R.<x> = PolynomialRing(Zmod(n))
    f = (A + B*x)^3 - c

    # Find small roots
    X = 2^(8 * unknown_len)
    roots = f.monic().small_roots(X=X, beta=1.0, epsilon=0.05)

    if roots:
        unknown = int(roots[0]).to_bytes(unknown_len, 'big')
        flag = prefix + unknown + suffix
```

---

## Key Takeaway

**Null padding with small exponents is dangerous.** The vulnerability arises because:
- Coppersmith's algorithm finds small roots efficiently using lattice reduction
- Known structure (prefix/suffix) dramatically reduces the search space
- Proper padding like OAEP randomizes the message, preventing this attack

The bound for recoverable plaintext is approximately n^(1/e), which for e=3 allows recovering ~1/3 of n's bits.
