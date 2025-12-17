# No Difference (175 pts)

**Category:** Hash Functions — Collisions
**Difficulty:** Hard

---

## Challenge

Create two PDF files that:
- Have identical MD5 hashes
- Display different visual content

---

## Vulnerability

This is an **identical-prefix collision** attack on PDF files. PDFs support incremental updates, where new content can override previous content. Combined with MD5 collisions, we can create "polyglot" PDFs.

**UniColl technique:** Creates two files with identical prefixes that diverge at a collision point, then converge to different content.

---

## Solution

```python
# Using UniColl (identical-prefix collision generator)
# This exploits PDF's structure to show different content

# PDF structure for collision:
# [Common header]
# [Collision block 1] -> renders as "PASS"
# [Collision block 2] -> renders as "FAIL"
# [Common trailer]

# The collision blocks differ but produce same MD5
# PDF viewer interprets one path based on internal byte differences
```

**PDF-specific technique:**
```
%PDF-1.4
[collision block with conditional rendering]

% If collision bit is 0: show image A
% If collision bit is 1: show image B

% Both PDFs have identical MD5 but display differently
```

**Tools:**
- **HashClash** - UniColl implementation
- **pdf-collider** - PDF-specific collision tool

---

## Key Takeaway

**Document format attacks combine crypto weaknesses with parser behavior:**
1. MD5 collision provides identical hashes
2. PDF's flexibility allows conditional content
3. Result: visually different documents with identical signatures

This attack was used in the "Flame" malware (2012) to forge Windows Update certificates. Real-world impact: attackers can sign malicious documents that verify as legitimate.
