# Merkle Trees (25 pts)

**Category:** Hash Functions — Hash-based Crypto
**Difficulty:** Easy

---

## Challenge

Verify Merkle tree proofs and reconstruct data from them.

---

## Vulnerability

Standard Merkle tree verification: given leaf values and authentication path, verify against root hash. This challenge tests understanding of Merkle tree structure.

**Tree structure:**
```
        Root
       /    \
    H(a+b)  H(c+d)
    /  \    /  \
   a    b  c    d
```

---

## Solution

```python
from hashlib import sha256

def hash256(data):
    return sha256(data).digest()

def merge_nodes(a, b):
    return hash256(a + b)

def verify_proof(a_hex, b_hex, c_hex, d_hex, root_hex):
    """Verify if SHA256(SHA256(a+b) + SHA256(c+d)) == root"""
    a = bytes.fromhex(a_hex)
    b = bytes.fromhex(b_hex)
    c = bytes.fromhex(c_hex)
    d = bytes.fromhex(d_hex)
    root = bytes.fromhex(root_hex)

    left = merge_nodes(a, b)
    right = merge_nodes(c, d)
    computed_root = merge_nodes(left, right)

    # If matches, bit is 1, else 0
    return 1 if computed_root == root else 0

# Parse proofs and extract bits
bits = []
for proof in proofs:
    a, b, c, d, root = proof
    bits.append(verify_proof(a, b, c, d, root))

# Convert bits to flag
flag = bits_to_bytes(bits)
```

**Steps:**
1. Parse each Merkle proof from the output
2. Verify each proof by computing the root hash
3. Valid proofs represent 1s, invalid represent 0s
4. Convert bit sequence to ASCII flag

---

## Key Takeaway

**Merkle trees enable efficient verification of large datasets.** Each leaf can be verified with O(log n) hashes. Without domain separation between leaf and internal nodes, second-preimage attacks are possible (not exploited here, but important for real implementations).
