# RSA Challenges

## Progress Summary
- **Completed**: 26/27 challenges
- **Total Points**: 2220/2395 pts

## Challenge Status

### Starter (110 pts) - 6/6 COMPLETE
| # | Challenge | Points | Status | Attack |
|---|-----------|--------|--------|--------|
| 01 | Modular Exponentiation | 10 | DONE | pow(base, exp, mod) |
| 02 | Public Keys | 15 | DONE | n = p × q |
| 03 | Euler's Totient | 20 | DONE | φ(n) = (p-1)(q-1) |
| 04 | Private Keys | 20 | DONE | d = e^(-1) mod φ(n) |
| 05 | RSA Decryption | 20 | DONE | m = c^d mod n |
| 06 | RSA Signatures | 25 | DONE | s = m^d mod n |

### Primes Part 1 (150 pts) - 5/5 COMPLETE
| # | Challenge | Points | Status | Attack |
|---|-----------|--------|--------|--------|
| 07 | Factoring | 15 | DONE | factordb.com or ECM |
| 08 | Inferius Prime | 30 | DONE | Small primes, factordb |
| 09 | Monoprime | 30 | DONE | n = p, φ(n) = p-1 |
| 10 | Square Eyes | 35 | DONE | n = p², take √n |
| 11 | Manyprime | 40 | DONE | Many small primes, ECM |

### Public Exponent (490 pts) - 6/6 COMPLETE
| # | Challenge | Points | Status | Attack |
|---|-----------|--------|--------|--------|
| 12 | Salty | 20 | DONE | e=1, c = m |
| 13 | Modulus Inutilis | 50 | DONE | e=3, m³ < n, cube root |
| 14 | Everything is Big | 70 | DONE | Large e → small d, Wiener |
| 19 | Crossed Wires | 100 | DONE | Factor N with private key |
| 20 | Everything is Still Big | 100 | DONE | Wiener attack at boundary |
| 21 | Endless Emails | 150 | DONE | Håstad broadcast attack, CRT |

### Primes Part 2 (440 pts) - 5/5 COMPLETE
| # | Challenge | Points | Status | Attack |
|---|-----------|--------|--------|--------|
| 15 | Infinite Descent | 50 | DONE | Fermat factorization |
| 16 | Marin's Secrets | 50 | DONE | Mersenne prime lookup |
| 22 | Fast Primes | 75 | DONE | ROCA-style, factordb |
| 23 | Ron was Wrong | 90 | DONE | Batch GCD attack |
| 28 | RSA Backdoor Viability | 175 | DONE | Cheng's 4p-1 CM factorization |

### Padding (200 pts) - 2/2 COMPLETE
| # | Challenge | Points | Status | Attack |
|---|-----------|--------|--------|--------|
| 26 | Bespoke Padding | 100 | DONE | Franklin-Reiter related message |
| 27 | Null or Never | 100 | DONE | Coppersmith stereotyped message |

### Signatures Part 1 (260 pts) - 3/3 COMPLETE
| # | Challenge | Points | Status | Attack |
|---|-----------|--------|--------|--------|
| 17 | Signing Server | 60 | DONE | Direct decryption as signature |
| 18 | Blinding Light | 120 | DONE | RSA blinding attack |
| 24 | Let's Decrypt | 80 | DONE | Custom n,e verification bypass |

### Signatures Part 2 (325 pts) - 1/2
| # | Challenge | Points | Status | Attack |
|---|-----------|--------|--------|--------|
| 25 | Vote for Pedro | 150 | DONE | Cube root forgery with e=3 |
| - | Let's Decrypt Again | 175 | TODO | Advanced signature oracle |

## Attack Reference

### Factorization Attacks
- **Small primes**: Use factordb.com or ECM
- **Fermat**: When p ≈ q, a² - n = b² reveals factors
- **Mersenne**: Check if n % (2^p - 1) = 0 for known exponents
- **ROCA**: CVE-2017-15361, weak TPM-generated primes
- **Batch GCD**: Find common factors across many moduli
- **Private key exposure**: e × d - 1 = k × φ(N) enables factoring

### Public Exponent Attacks
- **e = 1**: No encryption, c = m
- **e = 3, small m**: Cube root attack (no modular reduction)
- **Large e**: Wiener attack (continued fractions), d < n^0.25
- **Very large e**: Boneh-Durfee attack (lattice-based), d < n^0.292
- **Håstad**: Same m encrypted with different n, small e, use CRT

### Signature Attacks
- **Blinding**: Get signature of r^e × m via m' = r^e × m, then s/r
- **Forgery**: Existential forgery for m = s^e where s is chosen
- **Key substitution**: User-controlled verification parameters
- **Oracle abuse**: Use signing/verification oracle strategically

### Padding Attacks
- **Coppersmith**: Short padding attacks, known plaintext bits
- **Franklin-Reiter**: Related message attack with linear padding
- **Bleichenbacher**: PKCS#1 v1.5 padding oracle
- **Manger**: PKCS#1 v2.0 (OAEP) padding oracle

