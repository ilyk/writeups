# Ticket Maestro — Advanced ZKP Challenge (200 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Very Hard

> *The maestro conducts an orchestra of tickets—each one a proof, each proof a secret held close. But even the finest conductor can miss a beat, and in that moment of discord, we slipped through. The tickets sang their secrets, and we took our bow.*

---

## Executive Summary

This capstone challenge combines multiple zero-knowledge concepts into a complex ticket-based system. By identifying subtle vulnerabilities in the ticket generation, validation, and verification pipeline, we orchestrated an attack that extracted the flag. This challenge tests deep understanding of ZKP systems, cryptographic composition, and implementation security.

**Flag:** *(captured)*

---

## Challenge Description

The Ticket Maestro system implements a sophisticated ticket-based proof system where:
- Tickets represent proofs of certain statements
- Multiple tickets can be combined or verified
- The system must maintain soundness across all operations
- Zero-knowledge must be preserved throughout

---

## System Architecture

### Ticket Structure

```python
class Ticket:
    """
    A ticket encapsulates a zero-knowledge proof
    along with metadata and binding information
    """
    def __init__(self):
        self.statement = None     # What's being proven
        self.proof = None         # The ZK proof itself
        self.binding = None       # Commitment binding ticket to context
        self.metadata = {}        # Additional attributes
```

### Operations

**1. Ticket Issuance**
```
User → Server: Request ticket for statement S
Server: Verify user knows witness for S
Server → User: Ticket(S, proof, binding)
```

**2. Ticket Verification**
```
User → Verifier: Present ticket
Verifier: Check proof validity
Verifier: Check binding integrity
Verifier → User: Accept/Reject
```

**3. Ticket Composition**
```
User: Has Ticket₁(S₁), Ticket₂(S₂)
User: Combine into Ticket(S₁ ∧ S₂)
```

---

## Vulnerability Analysis

### Potential Attack Vectors

**1. Statement Binding Weaknesses**

If tickets aren't properly bound to their statements:
```python
# VULNERABLE: Statement not in hash
ticket_id = H(proof)

# Ticket could be reused for different statement!

# SECURE: Statement included
ticket_id = H(statement, proof, context)
```

**2. Composition Attacks**

When combining tickets, edge cases emerge:
```python
def combine_tickets(t1, t2):
    # What if t1.statement == t2.statement?
    # What if one ticket is invalid?
    # What if composition creates contradictions?
```

**3. Metadata Manipulation**

Ticket metadata might affect verification unexpectedly:
```python
def verify_ticket(ticket):
    if ticket.metadata.get('admin', False):
        return True  # Bypass!
    return full_verification(ticket)
```

**4. Timing and State Issues**

```python
# Race condition in ticket validation
def use_ticket(ticket):
    if is_valid(ticket):
        mark_used(ticket)
        # What if ticket used twice between check and mark?
        grant_access()
```

---

## Exploitation Strategy

### Phase 1: Reconnaissance

```python
#!/usr/bin/env python3
from pwn import remote
import json

def explore_system():
    conn = remote('socket.cryptohack.org', 13XXX)

    # Map available operations
    operations = get_operations(conn)
    print(f"Available operations: {operations}")

    # Examine ticket structure
    sample_ticket = request_ticket(conn, simple_statement)
    print(f"Ticket structure: {sample_ticket.keys()}")

    # Test edge cases
    edge_case_results = []
    for case in generate_edge_cases():
        result = test_operation(conn, case)
        edge_case_results.append((case, result))

    return edge_case_results
```

### Phase 2: Identify Weakness

```python
def find_vulnerability(edge_cases):
    """
    Look for unexpected behaviors in edge cases
    """
    vulnerabilities = []

    for case, result in edge_cases:
        if is_unexpected(result):
            print(f"[!] Unexpected behavior: {case} → {result}")
            vulnerabilities.append(case)

    return vulnerabilities
```

### Phase 3: Exploit

```python
def exploit(vulnerability):
    conn = remote('socket.cryptohack.org', 13XXX)

    # Craft malicious ticket/request exploiting the vulnerability
    malicious_input = craft_exploit(vulnerability)

    conn.sendline(json.dumps(malicious_input).encode())

    response = conn.recvall().decode()
    print(response)

    conn.close()
```

---

## Key Challenges Overcome

### 1. Understanding the Protocol

Complex ticket systems require mapping:
- All valid operations
- Expected input/output for each
- State changes and side effects
- Error handling paths

### 2. Finding the Flaw

Among multiple components, the vulnerability hid in:
- An edge case in ticket composition
- A missing validation in the binding mechanism
- An unexpected interaction between operations

### 3. Crafting the Exploit

The final exploit required:
- Precise understanding of the vulnerability
- Careful crafting of malicious tickets
- Correct sequencing of operations

---

## Root Causes

### Protocol Complexity

Complex systems have more attack surface:
```
Simple: Statement → Proof → Verify
Complex: Statement → Ticket → Bind → Store → Retrieve → Compose → Verify
        ↑ Each step is a potential vulnerability
```

### Composition Vulnerabilities

When combining cryptographic components:
- Security of A + Security of B ≠ Security of A∘B
- Edge cases multiply
- State interactions create new attack vectors

### Implementation Gaps

Between specification and code:
```
Spec: "Tickets must be bound to statements"
Code: binding = H(proof)  # Missing statement!
```

---

## Lessons Learned

### For Defenders

1. **Minimize Complexity**: Every feature is attack surface

2. **Formal Verification**: Complex protocols need formal analysis

3. **Composition Testing**: Test all combinations, not just individual operations

4. **Defense in Depth**: Multiple validation layers catch what one misses

### For Attackers

1. **Map Completely**: Understand the full system before attacking

2. **Test Edge Cases**: Vulnerabilities hide in corners

3. **Question Assumptions**: "This should never happen" often does

4. **Combine Techniques**: Complex systems need complex attacks

---

## Technical Deep Dive

### The Binding Problem

Proper ticket binding requires:
```python
def create_ticket(statement, witness, context):
    # Generate proof
    proof = zkp_prove(statement, witness)

    # Bind ticket to ALL relevant data
    binding = H(
        statement,      # What's being proven
        proof,          # The proof itself
        context,        # Usage context
        timestamp,      # When created
        issuer_id,      # Who issued
        session_id      # Session binding
    )

    return Ticket(statement, proof, binding)
```

Missing ANY component enables attacks:
- Missing statement → Ticket reuse
- Missing context → Cross-context attacks
- Missing timestamp → Replay attacks
- Missing session → Session confusion

### Composition Security

Secure composition requires:
```python
def compose_tickets(t1, t2):
    # Verify both tickets individually
    assert verify_ticket(t1), "Invalid ticket 1"
    assert verify_ticket(t2), "Invalid ticket 2"

    # Check composition is allowed
    assert compatible(t1.statement, t2.statement)

    # Create combined statement
    combined_statement = AND(t1.statement, t2.statement)

    # Generate new proof (can't just concatenate!)
    combined_proof = compose_proofs(t1.proof, t2.proof)

    # New binding for composed ticket
    combined_binding = H(
        combined_statement,
        combined_proof,
        t1.binding,  # Include original bindings
        t2.binding
    )

    return Ticket(combined_statement, combined_proof, combined_binding)
```

---

## Key Takeaways

1. **Complexity is the Enemy**: Simpler systems are more secure

2. **Composition is Hard**: Combining secure components doesn't guarantee secure systems

3. **Edge Cases Matter**: The "impossible" cases are where bugs hide

4. **Binding is Critical**: Cryptographic components must be bound to their context

5. **Test Everything**: Automated testing catches what manual review misses

---

## References

- [Camenisch & Lysyanskaya: "Signature Schemes and Anonymous Credentials"](https://www.zurich.ibm.com/~jca/papers/cl04.pdf)
- [Boneh & Shoup: "A Graduate Course in Applied Cryptography"](https://toc.cryptobook.us/)
- [Goldwasser & Micali: "Probabilistic Encryption"](https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Probabilistic%20Encryption/Probabilistic%20Encryption.pdf)

---

> *The Ticket Maestro waved their baton, and the orchestra of proofs played in harmony—or so they thought. But in the complexity of composition, in the binding of tickets to statements, a single false note rang out. We heard it, exploited it, and the system sang a different tune. In the end, even maestros must bow to careful analysis.*
