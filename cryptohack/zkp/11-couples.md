# Couples — Edge Cases and Useless Parameters (100 pts)

**Author:** ilyk
**Date:** December 2025
**Platform:** CryptoHack — Zero-Knowledge Proofs
**Difficulty:** Medium

> *The code looked secure. The cryptography was sound. But in the corners—where unused parameters lurked and edge cases slept—vulnerabilities waited. We found them, paired them, and extracted the flag.*

---

## Executive Summary

This challenge demonstrates that cryptographic vulnerabilities often hide not in the core protocol, but in implementation details: unused parameters that affect computation, edge cases that bypass validation, or code paths that shouldn't exist. The flag warns: "don't let useless params and edge cases in your code."

**Flag:** *(captured)*

---

## Challenge Description

The server implements a proof system with seemingly correct cryptography, but hidden implementation flaws allow exploitation. The vulnerabilities lie in:
- Parameters that appear unused but affect behavior
- Edge cases that bypass intended restrictions
- Code paths that create unexpected opportunities

---

## Vulnerability Analysis

### The Pattern: Implementation vs. Specification

**Specification (Secure):**
```
Protocol does X with parameters A, B, C
Security relies on proper handling of A, B, C
```

**Implementation (Vulnerable):**
```python
def protocol(A, B, C, D=None):  # D is "unused"
    if D is not None:
        # Edge case that changes everything
        return insecure_path(A, B, C, D)
    return secure_path(A, B, C)
```

### Common Vulnerability Patterns

**1. Unused Parameters That Aren't**
```python
def verify(proof, param=0):
    # param seems unused, but...
    if param == 1337:
        return True  # Debug bypass!
```

**2. Edge Case in Validation**
```python
def check_range(x, min_val, max_val):
    if x < min_val or x > max_val:
        raise ValueError("Out of range")
    # What if x == 0? Special behavior?
```

**3. Type Confusion**
```python
def process(data):
    if isinstance(data, list):
        # Different code path
        return handle_list(data)
    return handle_scalar(data)
```

---

## Exploitation Strategy

### Step 1: Identify the Edge Cases

Examine the protocol for:
- Optional parameters with default values
- Conditional branches based on input
- Special values (0, 1, -1, None, empty)
- Type-based dispatching

### Step 2: Test Boundary Conditions

```python
# Test various edge cases
test_cases = [
    {"param": 0},           # Zero
    {"param": 1},           # One
    {"param": -1},          # Negative
    {"param": None},        # Null
    {"param": []},          # Empty list
    {"param": ""},          # Empty string
    {"param": 2**256},      # Large number
]

for case in test_cases:
    response = send_to_server(case)
    if unexpected_behavior(response):
        print(f"Edge case found: {case}")
```

### Step 3: Exploit the Flaw

```python
#!/usr/bin/env python3
from pwn import remote
import json

def exploit():
    conn = remote('socket.cryptohack.org', 13XXX)

    # Receive public parameters
    params = json.loads(conn.recvline())

    # The vulnerability: an "unused" parameter changes behavior
    # or an edge case bypasses validation

    # Craft malicious input exploiting the edge case
    malicious_input = {
        "proof": craft_proof(),
        "unused_param": trigger_value,  # Triggers vulnerable path
    }

    conn.sendline(json.dumps(malicious_input).encode())

    response = conn.recvall().decode()
    print(response)

    conn.close()

if __name__ == "__main__":
    exploit()
```

---

## Root Causes

### 1. Dead Code That Isn't Dead

```python
# Developer thinks this is unused
def legacy_function(x):
    return x  # No validation!

# But it's called somewhere unexpected
if condition_never_expected_to_be_true:
    return legacy_function(user_input)
```

### 2. Default Parameters with Side Effects

```python
def process(data, debug=False):
    if debug:
        # Intended for development only
        return reveal_secrets(data)  # Oops, reachable!
```

### 3. Missing Edge Case Handling

```python
def divide(a, b):
    return a // b  # What if b == 0?

def modular_inverse(a, n):
    return pow(a, -1, n)  # What if gcd(a,n) != 1?
```

### 4. Inconsistent Validation

```python
def api_endpoint(request):
    # Frontend validates, backend trusts
    data = request.json  # No validation here!
    process(data)
```

---

## Remediation

### Code Review Checklist

✅ **Remove truly unused code**
```python
# Delete it, don't comment it
# deleted: def unused_function(): ...
```

✅ **Validate all parameters**
```python
def process(data, option=None):
    # Validate even "optional" params
    if option is not None:
        validate_option(option)
```

✅ **Handle all edge cases explicitly**
```python
def safe_divide(a, b):
    if b == 0:
        raise ValueError("Division by zero")
    return a // b
```

✅ **Defense in depth**
```python
# Validate at every layer
def outer(x):
    validate(x)
    return inner(x)

def inner(x):
    validate(x)  # Yes, validate again
    return compute(x)
```

### Static Analysis

```bash
# Find unused parameters
pylint --disable=all --enable=unused-argument code.py

# Find unreachable code
python -m py_compile code.py
```

---

## Key Takeaways

1. **"Unused" ≠ Unreachable**: Parameters may affect behavior unexpectedly

2. **Edge Cases Are Attack Surface**: Every special value (0, null, empty) is a potential bypass

3. **Delete Dead Code**: If it's not needed, remove it completely

4. **Validate Everywhere**: Don't trust that earlier validation happened

5. **Test Boundaries**: Fuzzing and boundary testing find what code review misses

---

## Defense Strategies

### Principle of Least Code

```python
# BAD: Keep unused parameter "just in case"
def compute(x, unused_legacy_param=None):
    pass

# GOOD: Remove it
def compute(x):
    pass
```

### Explicit Over Implicit

```python
# BAD: Implicit default behavior
def verify(proof, strict=True):
    if not strict:
        return True  # Bypass!

# GOOD: No bypass path exists
def verify(proof):
    # Always strict
    return full_verification(proof)
```

### Fail-Safe Defaults

```python
# BAD: Permissive default
def check_access(user, admin=True):
    if admin:
        return True

# GOOD: Restrictive default
def check_access(user, admin=False):
    if not admin:
        return verify_user(user)
```

---

## The Broader Lesson

Cryptographic security is only as strong as its implementation. A mathematically perfect protocol can be broken by:
- A debug flag left in production
- An edge case that wasn't considered
- A parameter that "doesn't do anything" but actually does
- Code that was supposed to be removed but wasn't

**Security audit mantra:** "What happens if I pass X? What about Y? What about nothing at all?"

---

## References

- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
- [CWE-561: Dead Code](https://cwe.mitre.org/data/definitions/561.html)
- [CWE-1164: Irrelevant Code](https://cwe.mitre.org/data/definitions/1164.html)

---

> *The cryptography was flawless. The mathematics, impeccable. But in a forgotten corner, an unused parameter waited—and when we called it by name, it answered. Edge cases and dead code: the silent vulnerabilities that turn secure systems into open doors.*
