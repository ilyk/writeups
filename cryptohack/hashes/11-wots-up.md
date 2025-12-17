# WOTS Up (75 pts)

**Category:** Hash Functions — Hash-based Crypto
**Difficulty:** Medium

---

## Challenge

Forge a WOTS+ (Winternitz One-Time Signature) signature given an existing signature for a different message.

---

## Vulnerability

WOTS signatures use **hash chains**. Each signature element is a hash chain value at some position. Given a signature for message `m`, we can forge signatures for messages with "larger" nibble values by hashing further down the chain.

**WOTS structure:**
```
Secret:   sk[i]
Chain:    sk[i] -> H(sk[i]) -> H(H(sk[i])) -> ... -> pk[i]
          Position 0    1           2              w-1
```

If signature for `m` reveals chain position `k`, we can compute positions `k+1, k+2, ...` for "larger" messages.

---

## Solution

```python
def forge_signature(orig_sig, orig_msg, target_msg):
    """
    Forge signature for target_msg given signature for orig_msg
    Only works when target nibbles >= orig nibbles (can hash forward)
    """
    forged = []

    for i, (sig_elem, orig_nib, target_nib) in enumerate(
        zip(orig_sig, orig_msg_nibbles, target_msg_nibbles)
    ):
        delta = target_nib - orig_nib

        if delta < 0:
            raise ValueError("Cannot forge: target nibble smaller than original")

        # Hash forward delta times
        current = sig_elem
        for _ in range(delta):
            current = hash_func(current)

        forged.append(current)

    return forged
```

**Attack:**
1. Receive a valid signature for message `m`
2. Find target message `m'` where each nibble is >= corresponding nibble in `m`
3. For each signature element, hash forward by the difference
4. Submit forged signature

---

## Key Takeaway

**WOTS signatures are one-time for a reason.** Signing reveals hash chain intermediate values. With one signature, the attacker can forge signatures for all "larger" messages. This is why WOTS is used with Merkle trees (XMSS, LMS) to enable multiple signatures from one key.
