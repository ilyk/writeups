# Authenticated Handshake (40 pts)

**Category:** TLS Part 1
**Difficulty:** Hard

---

## Challenge

Complete the `client_finished.py` script to calculate the Client Finished `verify_data` for a TLS 1.3 handshake.

**Files provided:**
- `no-finished-tls3.cryptohack.org.pcapng` - PCAP without Client Finished message
- `keylogfile2.txt` - Session secrets including CLIENT_HANDSHAKE_TRAFFIC_SECRET
- `client_finished.py` - Template script to complete

---

## Solution

The Client Finished message contains a `verify_data` field that proves the client saw all handshake messages. Computing it requires:

1. **Extract all handshake messages** from the PCAP
2. **Decrypt encrypted server messages** using the session keys
3. **Compute the transcript hash** over all messages
4. **Derive finished_key** from CLIENT_HANDSHAKE_TRAFFIC_SECRET
5. **Calculate verify_data** = HMAC(finished_key, transcript_hash)

### Step 1: Extract Handshake Messages

The transcript includes these messages in order:
1. ClientHello (packet 8, plaintext)
2. ServerHello (packet 10, plaintext)
3. EncryptedExtensions (packet 10, encrypted)
4. Certificate (packet 10, encrypted)
5. CertificateVerify (packet 10, encrypted)
6. ServerFinished (packet 10, encrypted)

### Step 2: Decrypt Server Messages

TLS 1.3 uses AEAD (AES-256-GCM). Derive keys from SERVER_HANDSHAKE_TRAFFIC_SECRET:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

def hkdf_expand_label(secret, label, context, length):
    hkdf_label = struct.pack('>H', length)
    label_with_prefix = b"tls13 " + label
    hkdf_label += struct.pack('B', len(label_with_prefix)) + label_with_prefix
    hkdf_label += struct.pack('B', len(context)) + context
    hkdf = HKDFExpand(algorithm=hashes.SHA384(), length=length, info=hkdf_label)
    return hkdf.derive(secret)

server_write_key = hkdf_expand_label(server_hs_secret, b"key", b"", 32)
server_write_iv = hkdf_expand_label(server_hs_secret, b"iv", b"", 12)
```

For each encrypted record:
- Nonce = IV XOR sequence_number (12 bytes)
- AAD = record_type || version || length (5 bytes)
- Decrypt and strip trailing content type byte

### Step 3: Build Transcript and Compute verify_data

```python
transcript = (client_hello + server_hello + encrypted_extensions +
              certificate + certificate_verify + server_finished)

transcript_hash = hashlib.sha384(transcript).digest()

finished_key = HKDF_expand_label(client_hs_secret, b"finished", b"", 48, hashlib.sha384)

verify_data = hmac.new(finished_key, transcript_hash, hashlib.sha384).digest()
```

### Key Points

- Messages must include their 4-byte handshake headers (type + length)
- Exclude TLS record layer headers (5 bytes)
- Use SHA-384 for TLS_AES_256_GCM_SHA384
- Sequence numbers start at 0 and increment per encrypted record

---

## Key Takeaway

**The Finished message provides handshake integrity.** It cryptographically binds all handshake messages together, preventing any tampering. If an attacker modified any message, the verify_data calculation would fail, and the peer would reject the connection. This is a critical defense against man-in-the-middle attacks during the handshake.

**Reference:** [The Illustrated TLS 1.3 Connection](https://tls13.xargs.org/) provides excellent visual explanations of TLS 1.3 internals.
