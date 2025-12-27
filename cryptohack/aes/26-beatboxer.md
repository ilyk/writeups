# Beatboxer (150 pts)

**Category:** AES — Linear Cryptanalysis
**Difficulty:** Hard

---

## Challenge

Apply linear cryptanalysis to break a reduced-round block cipher.

---

## Vulnerability

Linear cryptanalysis exploits statistical biases in cipher components. If linear approximations of S-boxes hold with probability ≠ 0.5, plaintexts and ciphertexts can reveal key bits.

**Key insight:** Find a linear trail through the cipher where XOR of certain plaintext, ciphertext, and key bits equals 0 with biased probability.

---

## Solution

```python
def linear_cryptanalysis(encrypt_oracle, sbox, num_samples=10000):
    """
    Linear approximation: P[i1,i2,...] ⊕ C[j1,j2,...] ⊕ K[k1,k2,...] = 0

    1. Find best linear approximation for S-box
    2. Chain approximations through cipher rounds
    3. Collect plaintext-ciphertext pairs
    4. For each key guess, count bias
    5. Correct key has strongest bias
    """
    # Calculate S-box linear approximation table (LAT)
    lat = [[0] * 256 for _ in range(256)]
    for input_mask in range(256):
        for output_mask in range(256):
            count = 0
            for x in range(256):
                input_parity = bin(x & input_mask).count('1') % 2
                output_parity = bin(sbox[x] & output_mask).count('1') % 2
                if input_parity == output_parity:
                    count += 1
            lat[input_mask][output_mask] = count - 128  # Bias from 128

    # Find strongest linear approximation
    best_bias = max(abs(lat[i][j]) for i in range(1, 256) for j in range(1, 256))
    # ... continue attack
```

---

## Key Takeaway

**Linear cryptanalysis requires statistical weaknesses.** For AES:
- S-box is designed for maximum non-linearity
- Best linear approximation has bias 2^-6
- Attack requires 2^38 known plaintexts (infeasible)

Reduced-round or poorly-designed ciphers are vulnerable. Linear cryptanalysis is one of the key techniques in academic cipher analysis.

