# Hamiltonicity — Fiat-Shamir with Incomplete Statement Hashing (100 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Medium

> *The graph whispered its topology to the hash function. But the hash function, selective in its listening, heard only the edges—not the vertices that mattered. We proved knowledge of a cycle in a graph that had none, because the hash forgot to ask which graph.*

---

## Executive Summary

This challenge exposes a critical vulnerability in Fiat-Shamir transformation implementations: failure to include the complete statement being proven in the challenge hash. By exploiting this omission, we convinced the verifier that a graph *without* a Hamiltonian cycle actually contains one—we simply proved knowledge of a cycle in a *different* graph that we substituted during the protocol. The flag confirms: **not hashing the entire statement is bad**.

**Flag:** *(captured)*

---

## Challenge Description

The server implements a zero-knowledge proof of knowledge for Hamiltonian cycles using the Fiat-Shamir heuristic. The protocol aims to prove:

**Statement:** "I know a Hamiltonian cycle in graph `G`"

Where:
- `G` is an adjacency matrix representing a graph
- A Hamiltonian cycle is a path visiting each vertex exactly once and returning to start
- The proof should be non-interactive (Fiat-Shamir) and zero-knowledge

**The Catch:** The server's graph `G` does **NOT** have a Hamiltonian cycle, yet we must produce a valid proof.

---

## Protocol Overview

### Honest Hamiltonian Cycle ZKP

**Interactive Version (3-Colorability basis):**
1. **Commitment**: Prover commits to a permuted version of the graph
2. **Challenge**: Verifier randomly chooses:
   - `c = 0`: "Show me the permutation (prove you committed to an isomorphic graph)"
   - `c = 1`: "Show me the Hamiltonian cycle in the committed graph"
3. **Response**: Prover opens accordingly
4. **Verification**: Verifier checks consistency

**Fiat-Shamir Non-Interactive:**
- Challenge is derived via hash: `c = H(commitment, public_params)`
- Repeat for many rounds (e.g., 128) to achieve negligible soundness error

---

## Vulnerability Analysis

### The Critical Flaw

**Proper Fiat-Shamir Challenge:**
```python
c = H(G, commitment, round, public_params)
#     ↑ The statement being proven MUST be included!
```

**Flawed Implementation:**
```python
c = H(commitment, round, public_params)
#     ↑ Missing G! The hash doesn't know which graph we're proving about!
```

**Impact:**
Without `G` in the hash, the challenge `c` is computed identically for:
- A proof about graph `G₁` (no cycle)
- A proof about graph `G₂` (has cycle)

**Attack Idea:**
1. Find or construct a graph `G'` that **does** have a Hamiltonian cycle
2. Compute commitments and proofs for `G'`
3. Submit these proofs to the verifier expecting them to be about `G`
4. Since the hash doesn't include `G`, the verifier accepts proofs about `G'` as if they were about `G`

---

## Exploitation

### Step 1: Construct a Graph With a Cycle

```python
# Server's graph (NO Hamiltonian cycle)
G_server = [
    [0, 0, 1, 0, 0],
    [1, 0, 0, 0, 0],
    [0, 1, 0, 0, 0],
    [0, 0, 0, 0, 1],
    [0, 0, 0, 1, 0]
]

# Our substitute graph (HAS Hamiltonian cycle)
G_ours = [
    [0, 1, 1, 0, 1],
    [1, 0, 0, 0, 0],
    [0, 0, 0, 1, 0],
    [0, 1, 1, 0, 0],
    [1, 0, 1, 1, 0]
]

# Known cycle in G_ours: 0 → 4 → 2 → 3 → 1 → 0
cycle = [(0,4), (4,2), (2,3), (3,1), (1,0)]
```

### Step 2: Generate Valid Proofs for G_ours

For each of 128 rounds:
1. Commit to a permuted version of `G_ours`
2. Compute Fiat-Shamir challenge: `c = H(commitment, state)`
3. Generate response:
   - If `c = 0`: Open the permutation
   - If `c = 1`: Open the Hamiltonian cycle

```python
import random
from hamiltonicity import commit_to_graph, permute_graph, hash_committed_graph

numrounds = 128
proofs = []

for round_idx in range(numrounds):
    # Permute our graph randomly
    perm = list(range(5))
    random.shuffle(perm)

    # Commit to the permuted graph
    A, openings = commit_to_graph(G_ours, 5)
    A_perm = permute_graph(A, 5, perm)

    # Compute challenge (same as server's hash function)
    FS_state = hash_committed_graph(A_perm, FS_state, comm_params)
    challenge = FS_state[-1] & 1

    # Prepare proof based on challenge
    if challenge == 1:
        # Open Hamiltonian cycle
        permuted_cycle = apply_permutation(cycle, perm)
        r_vals = get_r_values(openings, cycle)
        proof = {"A": A_perm, "z": [permuted_cycle, r_vals]}
    else:
        # Open permutation
        openings_perm = permute_graph(openings, 5, perm)
        proof = {"A": A_perm, "z": [perm, openings_perm]}

    proofs.append(proof)
```

### Step 3: Submit Proofs to Server

```python
#!/usr/bin/env python3
from pwn import remote
import json

conn = remote('socket.cryptohack.org', 13429)
conn.recvuntil(b'Prove you know a Hamiltonian cycle!')

# Send all 128 proofs
for proof in proofs:
    conn.recvuntil(b'send fiat shamir proof:')
    conn.sendline(json.dumps(proof).encode())

# Receive flag
response = conn.recvall(timeout=30).decode()
print(response)

# Flag received upon successful exploitation
```

---

## Root Causes

1. **Incomplete Hash Input**: The Fiat-Shamir challenge hash omits the statement `G`, allowing proof substitution
2. **Statement Ambiguity**: Without `G` in the hash, the verifier cannot distinguish proofs about different graphs
3. **No Binding to Statement**: The commitment is not cryptographically bound to the specific statement being proven
4. **Missing Security Proof**: A proper security analysis would have caught this—the proof would not reduce to hardness assumptions without statement binding

---

## Remediation

### Immediate Fix

**Include Full Statement in Hash:**
```python
def fiat_shamir_challenge(G, commitment, state, params):
    """
    Compute Fiat-Shamir challenge with COMPLETE statement
    """
    fs = sha256()
    fs.update(json.dumps(G).encode())  # ← Critical: hash the graph!
    fs.update(state)
    fs.update(commitment_to_bytes(commitment))
    fs.update(str(params).encode())
    return fs.digest()
```

### Broader Security Principles

1. **Hash Everything Public**:
   ```
   c = H(statement, public_params, commitment, context, nonce)
   ```

2. **Domain Separation**:
   ```python
   H("HAMILTONIAN_CYCLE_PROOF" || G || commitment || ...)
   ```

3. **Formal Specification**:
   - Clearly define what constitutes the "statement"
   - Include ALL statement components in the hash
   - Document why each element is included

4. **Security Proof Requirements**:
   - Prove that the Fiat-Shamir transformed protocol is sound
   - Show that the hash input uniquely identifies the statement
   - Verify that proof transcripts for different statements are independent

---

## Impact Analysis

**Severity:** Critical

- **Soundness Broken**: Prover can prove false statements
- **Graph Substitution**: Can prove properties of one graph while claiming another
- **Zero-Knowledge Preserved**: Interestingly, ZK property may still hold (simulator can still work)—but soundness failure makes this moot

**Real-World Analogues:**
- Signature schemes that don't hash the message
- Certificate verification that doesn't check the subject
- Authentication tokens that don't bind to user identity

---

## Comparison: Flawed vs. Secure

| Component | Flawed Implementation | Secure Implementation |
|-----------|----------------------|----------------------|
| **Hash Input** | `H(commitment, state)` | `H(G, commitment, state)` |
| **Statement Binding** | ❌ None | ✅ Cryptographic |
| **Soundness** | ❌ Broken (graph substitution) | ✅ Provably secure |
| **Attack Resistance** | ❌ This writeup | ✅ Resistant |

---

## Key Takeaways

- **Hash the Full Statement**: Fiat-Shamir challenges MUST include everything public and relevant to the statement
- **Statement Identity Matters**: Without binding proofs to specific statements, they become universal forgeries
- **Cryptographic Hygiene**: "Include it in the hash" is a simple rule that prevents entire attack classes
- **Formalism Saves**: A formal security proof would have immediately revealed this vulnerability

---

## Testing for This Vulnerability

**Red Team Checklist:**
```python
# When auditing ZK implementations:

1. Identify the statement being proven
2. Find the Fiat-Shamir hash computation
3. Check: Is EVERY component of the statement included?
4. If not: attempt proof substitution
5. Verify: Can you prove about statement S1 but claim it's about S2?
```

---

## References

- [Fiat-Shamir Transform](https://link.springer.com/chapter/10.1007/3-540-47721-7_12)
- [Common Pitfalls in Fiat-Shamir](https://eprint.iacr.org/2023/691)
- [Zero-Knowledge Proof Systems](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.html)
- [Hamiltonian Cycle ZKP](https://en.wikipedia.org/wiki/Zero-knowledge_proof#Hamiltonian_cycle_for_undirected_graphs)

---

## Appendix: Full Exploit Code

```python
#!/usr/bin/env python3
"""
Exploit: Hamiltonicity proof with incomplete Fiat-Shamir hashing
We prove knowledge of a cycle in G' and submit it as proof for G
"""
import sys
sys.path.insert(0, '/path/to/crypto/utils')

from hamiltonicity import commit_to_graph, permute_graph, hash_committed_graph
from hamiltonicity import comm_params, get_r_vals
import json
import random
from pwn import remote

N = 5
numrounds = 128

# Graph that DOES have a Hamiltonian cycle
G_has_cycle = [
    [0,1,1,0,1],
    [1,0,0,0,0],
    [0,0,0,1,0],
    [0,1,1,0,0],
    [1,0,1,1,0]
]
known_cycle = [(0,4), (4,2), (2,3), (3,1), (1,0)]

# Generate valid proofs for G_has_cycle
FS_state = b''
proofs = []

for i in range(numrounds):
    # Permute and commit
    perm = list(range(N))
    random.shuffle(perm)

    A, openings = commit_to_graph(G_has_cycle, N)
    A_perm = permute_graph(A, N, perm)

    # Compute challenge
    FS_state = hash_committed_graph(A_perm, FS_state, comm_params)
    challenge = FS_state[-1] & 1

    # Generate response
    if challenge == 1:
        # Open cycle
        permuted_cycle = [[perm.index(s), perm.index(d)] for s, d in known_cycle]
        r_vals = get_r_vals(openings, N, known_cycle)
        z = [permuted_cycle, r_vals]
    else:
        # Open permutation
        z = [perm, permute_graph(openings, N, perm)]

    proofs.append(json.dumps({"A": A_perm, "z": z}))

# Send to server (which expects proof for G_no_cycle)
conn = remote('socket.cryptohack.org', 13429)
conn.recvuntil(b'hamiltonian cycle!')

for proof in proofs:
    conn.recvuntil(b'send fiat shamir proof:')
    conn.sendline(proof.encode())

flag = conn.recvall(timeout=30).decode()
print(flag)

conn.close()
```

---

> *The verifier checked our commitments, our openings, our algebra. All correct. But it never asked: "Which graph?" The hash, silent on the matter, accepted our substitution. We proved a cycle in Graph A while claiming Graph B. The flag arrived, bearing its own proof: `not_hashing_entire_statement_is_bad`. Indeed.*
