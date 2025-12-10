# Mister Saplin's The Prover — Merkle Tree Negative Index Attack (125 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Medium-Hard

> *The index was checked for bounds. But Python whispers in negative, and the tree's internal secrets spilled into places they were never meant to go.*

---

## Executive Summary

This challenge implements a custom "Saplin" (Merkle-like) proof system where the prover must demonstrate knowledge of the root. The server allows previewing one leaf hash, but a negative index vulnerability combined with deterministic leaf content allows extracting enough information to forge the root without knowing the full secret.

**Flag:** *(captured and verified)*

---

## Challenge Description

The server constructs a Merkle tree from 64 bytes of data:
- 17 bytes of random secret
- 47 bytes of FLAG

Data is split into 8 chunks of 8 bytes each, hashed into leaves, then merged up the tree to produce a root.

**Protocol:**
1. `get_node`: Preview ONE leaf hash (indices 0-7), limited to single use
2. `do_proof`: Submit the root hash to prove knowledge

**The Catch:**
We only get one leaf preview, but need the entire tree structure to compute the root.

---

## Vulnerability Analysis

### Bug 1: Negative Index Bypass

```python
if not self.preview_used and wanted_node < len(self.nodes[0])-1:
    node = self.nodes[0][wanted_node].hex()
```

The bounds check `wanted_node < len(self.nodes[0])-1` only verifies upper bound!

- `len(self.nodes[0]) - 1 = 8` (after internal nodes appended)
- `-1 < 8` is **True** in Python
- `self.nodes[0][-1]` returns the **last element**

After `build_saplin()`, the tree structure is:

```
nodes[0] = [leaf0, leaf1, ..., leaf7, nodes[1][0]]  # 9 elements!
nodes[1] = [H(leaf0||leaf1), ..., nodes[2][0]]      # 5 elements
nodes[2] = [H(layer1[0]||layer1[1]), layer1[2]||layer1[3]), nodes[3][0]]
nodes[3] = [root]
```

Using `node=-1` gives us `nodes[0][-1] = nodes[1][0] = H(leaf0 || leaf1)`!

This is an **internal node**, not a leaf—bypassing the intended restriction.

### Bug 2: Deterministic Leaf Content

The 64-byte data layout:

| Chunk | Bytes | Content |
|-------|-------|---------|
| 0 | 0-7 | `secret[0:8]` — random |
| 1 | 8-15 | `secret[8:16]` — random |
| 2 | 16-23 | `secret[16:17]` + `FLAG[0:7]` — 1 random byte + "crypto{" |
| 3 | 24-31 | `FLAG[7:15]` — **deterministic** |
| 4 | 32-39 | `FLAG[15:23]` — **deterministic** |
| 5 | 40-47 | `FLAG[23:31]` — **deterministic** |
| 6 | 48-55 | `FLAG[31:39]` — **deterministic** |
| 7 | 56-63 | `FLAG[39:47]` — **deterministic** |

**Key insight:** Leaves 3-7 are the same for ALL connections!

---

## Exploitation Strategy

### Attack Plan

1. **Connection A**: Use `node=-1` to get `H(leaf0 || leaf1)` (internal node)
2. **Connections B-F**: Get leaves 3, 4, 5, 6, 7 (deterministic across connections)
3. **Brute force**: Leaf 2 has only 256 variants (1 random byte + "crypto{")
4. **Reconstruct root**: Compute for connection A and submit

### Tree Reconstruction

Given:
- `nodes[1][0] = H(leaf0 || leaf1)` — from negative index
- `leaf3, leaf4, leaf5, leaf6, leaf7` — from other connections
- `leaf2` — brute force 256 options

Compute:
```
layer1[0] = nodes[1][0]          # We have this!
layer1[1] = H(leaf2 || leaf3)    # Brute force leaf2
layer1[2] = H(leaf4 || leaf5)    # Known
layer1[3] = H(leaf6 || leaf7)    # Known

layer2[0] = H(layer1[0] || layer1[1])
layer2[1] = H(layer1[2] || layer1[3])  # Fully known!

root = H(layer2[0] || layer2[1])
```

---

## Proof of Concept

```python
#!/usr/bin/env python3
from pwn import remote
import json
from hashlib import sha256

def hash256(data):
    return sha256(data).digest()

def merge_nodes(a, b):
    return hash256(a + b)

def reconstruct_root(leaf0_1_merged, leaf2, leaf3, leaf4, leaf5, leaf6, leaf7):
    """Reconstruct root given merged node for leaves 0-1, and individual leaves 2-7"""
    layer1_0 = leaf0_1_merged
    layer1_1 = merge_nodes(leaf2, leaf3)
    layer1_2 = merge_nodes(leaf4, leaf5)
    layer1_3 = merge_nodes(leaf6, leaf7)

    layer2_0 = merge_nodes(layer1_0, layer1_1)
    layer2_1 = merge_nodes(layer1_2, layer1_3)

    return merge_nodes(layer2_0, layer2_1)

# Phase 1: Get internal node via negative index
print("[*] Phase 1: Getting nodes[1][0] via negative index")
main_conn = remote('socket.cryptohack.org', 13432, level='warn')
main_conn.recvuntil(b'implementation\n')

main_conn.sendline(json.dumps({"option": "get_node", "node": -1}).encode())
resp = json.loads(main_conn.recvline().decode().strip())
node_1_0 = bytes.fromhex(resp["msg"])
print(f"[+] Got nodes[1][0]: {node_1_0.hex()[:32]}...")

# Phase 2: Get deterministic leaves from other connections
print("\n[*] Phase 2: Getting deterministic leaves 3-7")
deterministic_leaves = {}

for leaf_idx in [3, 4, 5, 6, 7]:
    conn = remote('socket.cryptohack.org', 13432, level='warn')
    conn.recvuntil(b'implementation\n')
    conn.sendline(json.dumps({"option": "get_node", "node": leaf_idx}).encode())
    resp = json.loads(conn.recvline().decode().strip())
    deterministic_leaves[leaf_idx] = bytes.fromhex(resp["msg"])
    conn.close()

# Phase 3: Brute force leaf 2
print("\n[*] Phase 3: Brute forcing leaf 2 (256 options)")
FLAG_PREFIX = b"crypto{"

for random_byte in range(256):
    chunk2 = bytes([random_byte]) + FLAG_PREFIX
    leaf2 = hash256(chunk2)

    root = reconstruct_root(
        node_1_0, leaf2,
        deterministic_leaves[3],
        deterministic_leaves[4],
        deterministic_leaves[5],
        deterministic_leaves[6],
        deterministic_leaves[7]
    )

    main_conn.sendline(json.dumps({"option": "do_proof", "root": root.hex()}).encode())
    resp = json.loads(main_conn.recvline().decode().strip())

    if "crypto{" in str(resp.get("msg", "")):
        print(f"\n[+] FOUND! Random byte: {random_byte} (0x{random_byte:02x})")
        print(f"[+] FLAG: {resp['msg']}")
        break

main_conn.close()
```

**Result:** Flag captured on brute force iteration 27 (0x1b).

---

## Root Causes

1. **Incomplete Bounds Check**: `wanted_node < upper` without `wanted_node >= 0` allows negative indexing
2. **Data Structure Leakage**: Appending internal nodes to `nodes[0]` makes them accessible via negative indices
3. **Deterministic Chunks**: FLAG bytes without randomization create predictable leaves across connections
4. **No Connection Binding**: Leaf values are connection-independent, allowing cross-connection information gathering

---

## Remediation

### Immediate Fixes

```python
# Fix 1: Proper bounds check
if not self.preview_used and 0 <= wanted_node < len(self.nodes[0]) - 1:

# Fix 2: Type check
if not isinstance(wanted_node, int) or wanted_node < 0:
    return {"error": "Invalid node index"}

# Fix 3: Don't expose internal nodes
if wanted_node >= 8:  # Only allow leaf indices
    return {"error": "Invalid node index"}
```

### Design Improvements

1. **Randomize All Chunks**: Include random padding in every chunk, not just the secret portion
2. **Per-Connection Nonces**: Bind tree construction to connection-specific randomness
3. **Separate Data Structures**: Don't append internal nodes to leaf arrays
4. **Rate Limiting**: Prevent brute-force attempts across multiple connections

---

## Key Takeaways

- **Python Indexing is Dangerous**: Negative indices are valid and wrap around—always check `>= 0`
- **Information Leakage Across Connections**: If data is deterministic, attackers can combine information from multiple sessions
- **Defense in Depth**: Multiple small vulnerabilities (negative index + deterministic data + unlimited connections) chain into full compromise
- **Merkle Trees Need Care**: Internal node exposure breaks the "commitment before reveal" property

---

## Attack Flow Diagram

```
Connection A:                     Connections B-F:
┌──────────────┐                 ┌──────────────┐
│ get_node(-1) │                 │ get_node(3)  │
│      ↓       │                 │ get_node(4)  │
│ nodes[1][0]  │                 │ get_node(5)  │
│ =H(L0||L1)   │                 │ get_node(6)  │
└──────┬───────┘                 │ get_node(7)  │
       │                         └──────┬───────┘
       │                                │
       │    ┌────────────────────┐      │
       └───►│ Reconstruct Tree   │◄─────┘
            │ Brute force leaf 2 │
            │ (256 options)      │
            └─────────┬──────────┘
                      │
                      ▼
            ┌─────────────────┐
            │ Submit root to  │
            │ Connection A    │
            │      ↓          │
            │    FLAG!        │
            └─────────────────┘
```

---

## References

- [Merkle Trees in Cryptography](https://en.wikipedia.org/wiki/Merkle_tree)
- [Python Negative Indexing Gotchas](https://docs.python.org/3/tutorial/introduction.html#strings)
- [CWE-129: Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html)

---

> *The tree stood tall, its leaves protected by bounds. But the gardener forgot: in Python's garden, -1 points not to emptiness, but to the very last branch.*
