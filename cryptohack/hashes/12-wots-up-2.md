# WOTS Up 2 (90 pts)

**Category:** Hash Functions — Hash-based Crypto
**Difficulty:** Medium-Hard

---

## Challenge

Advanced WOTS+ forgery with checksum protection.

---

## Vulnerability

WOTS+ adds a **checksum** to prevent the basic forgery attack. The checksum increases when message nibbles decrease. However, if we can find a message where:
1. Message nibbles allow forward hashing
2. Checksum nibbles also allow forward hashing

We can still forge.

**Checksum calculation:**
```
checksum = sum(w - 1 - m[i] for all nibbles)
```

When we increase message nibbles, checksum decreases, which means checksum signature elements can be hashed forward.

---

## Solution

```python
def compute_checksum(msg_nibbles, w):
    """Compute WOTS+ checksum"""
    return sum(w - 1 - n for n in msg_nibbles)

def can_forge(orig_msg, target_msg, w):
    """Check if target can be forged from original"""
    orig_nibbles = msg_to_nibbles(orig_msg)
    target_nibbles = msg_to_nibbles(target_msg)

    # Check message nibbles (must increase or stay same)
    for o, t in zip(orig_nibbles, target_nibbles):
        if t < o:
            return False

    # Check checksum (must decrease or stay same)
    orig_cs = compute_checksum(orig_nibbles, w)
    target_cs = compute_checksum(target_nibbles, w)

    orig_cs_nibbles = int_to_nibbles(orig_cs)
    target_cs_nibbles = int_to_nibbles(target_cs)

    for o, t in zip(orig_cs_nibbles, target_cs_nibbles):
        if t < o:
            return False

    return True

def find_forgeable_message(orig_msg, w):
    """Search for a message that can be forged"""
    for target in candidate_messages():
        if can_forge(orig_msg, target, w):
            return target
    return None
```

**Attack:**
1. Analyze the original message's nibbles and checksum
2. Search for target messages where:
   - All message nibbles >= original
   - All checksum nibbles <= original checksum nibbles
3. Forge by hashing forward appropriately

---

## Key Takeaway

**Checksums mitigate but don't eliminate WOTS forgery.** The checksum adds constraints, but carefully chosen messages can still satisfy both the message and checksum requirements for forgery. This is why WOTS should truly be used only once per key pair.
