# Collider (50 pts)

**Category:** Hash Functions — Collisions
**Difficulty:** Easy

---

## Challenge

Find two different messages with the same MD5 hash.

---

## Vulnerability

MD5 has been cryptographically broken since 2004. Wang et al. demonstrated the first practical collision attack, and tools like **fastcoll** can generate collisions in seconds.

**Key insight:** MD5 collisions exist in pairs of 128-byte blocks that differ in specific bit positions but produce identical hashes.

---

## Solution

```python
# Option 1: Use known collision pairs
# Wang et al.'s original collision (hex-encoded)
msg1 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
)
msg2 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
)

from hashlib import md5
assert md5(msg1).hexdigest() == md5(msg2).hexdigest()
assert msg1 != msg2

# Option 2: Generate fresh collision using fastcoll
# $ fastcoll -o msg1.bin msg2.bin
```

---

## Key Takeaway

**MD5 is completely broken for collision resistance.** Modern tools generate collisions in under a second on consumer hardware. MD5 should never be used for:
- Digital signatures
- Certificate validation
- Any application requiring collision resistance

MD5 is still okay for checksums (integrity against accidental corruption) but not against adversaries.
