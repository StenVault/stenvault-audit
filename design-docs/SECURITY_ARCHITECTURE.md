# CloudVault — Security Architecture Reference

**Purpose**: This document describes the cryptographic architecture that the audit pipeline validates against. It serves as the ground truth for the triage layer's false positive detection — findings that match documented design decisions are suppressed.

---

## Zero-Knowledge Model

The server never sees file contents, filenames, or user passwords. All encryption and decryption happens exclusively on the client device.

### Trust Boundary

```
┌──── CLIENT (TRUSTED) ────────────────────────────────┐
│  ✓ Plaintext files, filenames, passwords              │
│  ✓ Master Key (32 bytes, in memory only)              │
│  ✓ File encryption keys (per-file, ephemeral)         │
│  ✓ Hybrid secret keys (X25519 + ML-KEM-768)          │
│  ✓ Signature secret keys (Ed25519 + ML-DSA-65)       │
└───────────────────────┬──────────────────────────────┘
                        │ HTTPS (TLS 1.3)
                        │ Only ciphertext crosses
┌──── SERVER (UNTRUSTED) ┴─────────────────────────────┐
│  ✗ NEVER sees: plaintext, filenames, passwords        │
│  ✗ NEVER sees: master key, file keys, secret keys     │
│  ✓ Sees: encrypted blobs, wrapped keys, public keys  │
│  ✓ Sees: KDF salt, IVs, encryption version           │
└──────────────────────────────────────────────────────┘
```

---

## Cryptographic Primitives

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| File encryption | AES-256-GCM | NIST SP 800-38D |
| Key derivation (password) | Argon2id | RFC 9106 |
| Key wrapping | AES-KW | RFC 3394 |
| Key derivation (shared secrets) | HKDF-SHA256 | RFC 5869 |
| Classical key exchange | X25519 (ECDH) | RFC 7748 |
| Post-quantum key encapsulation | ML-KEM-768 | FIPS 203 |
| Classical digital signature | Ed25519 | RFC 8032 |
| Post-quantum digital signature | ML-DSA-65 | FIPS 204 |
| Password authentication | OPAQUE | RFC 9807 |
| Time-based OTP | TOTP | RFC 6238 |
| Content integrity | HMAC-SHA256 | RFC 2104 |
| Secret sharing | Shamir over GF(2^8) | Shamir (1979) |

---

## Key Hierarchy

```
User Password (never leaves browser)
│
├── Argon2id(password, salt)
│   memoryCost=47104 KiB (46 MiB), timeCost=1, parallelism=1
│   │
│   └── KEK (Key Encryption Key, 32 bytes)
│       │
│       └── AES-KW Unwrap → Master Key (MK, 32 bytes)
│                             │
│                             ├── HKDF("file-enc") → File Encryption Keys (V3)
│                             ├── HKDF("filename") → Filename Encryption Key
│                             ├── AES-KW Wrap → X25519 secret (32B)
│                             ├── AES-256-GCM → ML-KEM-768 secret (2400B)
│                             ├── AES-KW Wrap → Ed25519 secret (32B)
│                             ├── AES-256-GCM → ML-DSA-65 secret (4032B)
│                             └── AES-KW Wrap → Organization Master Key
│
└── [UES Fast Path] → Device-KEK (~100ms vs ~500ms)
```

**Key size constraint**: AES-KW (RFC 3394) only handles keys up to ~64 bytes. Post-quantum secret keys (ML-KEM-768 = 2,400B, ML-DSA-65 = 4,032B) use AES-256-GCM with separate IVs instead.

**Password change**: Only the MK wrapping changes — files are NOT re-encrypted.

---

## File Encryption V4 — Hybrid PQC

Per-file ephemeral keys with dual key exchange (classical + quantum-resistant):

```
Sender:
├── Ephemeral X25519 keypair → ECDH shared secret (32B)
├── ML-KEM-768.Encapsulate → PQ shared secret (32B) + ciphertext (1088B)
├── HKDF-SHA256(classical || pq) → Hybrid KEK (32B)
├── Random file_key (32B) → AES-KW(hybrid_kek, file_key) → wrapped key
└── AES-256-GCM(file_key, IV, plaintext) → ciphertext

Decryptor:
├── ECDH(own_secret, ephemeral_public) → classical shared secret
├── ML-KEM-768.Decapsulate(own_secret, pq_ciphertext) → PQ shared secret
├── HKDF → hybrid_kek → AES-KW-Unwrap → file_key
└── AES-256-GCM-Decrypt → plaintext
```

Both classical AND quantum-resistant algorithms must be broken to recover the file key.

### CVEF Binary Format (v1.2)

```
Offset  Size     Field
0x00    4 bytes  Magic: "CVEF" (0x43 0x56 0x45 0x46)
0x04    1 byte   Format Version: 1
0x05    4 bytes  Metadata Length (big-endian uint32)
0x09    N bytes  Metadata JSON (algorithm, salt, IV, KEM params, signatures)
0x09+N  rest     Encrypted Data (AES-256-GCM chunks, 5 MiB each)
```

### Streaming Encryption

- 5 MiB chunks, each with unique IV derived from `HKDF(baseIV, chunkIndex)`
- Files >500 MB use multipart upload with independent chunk encryption
- Chunk index bound to prevent reordering attacks

---

## Filename Encryption

```
HKDF-SHA256(MasterKey, fileId, "cloudvault-filename") → per-file key
AES-256-GCM(FilenameKey, IV, filename) → encrypted filename
```

Server stores encrypted filenames and opaque placeholders. Client decrypts on-the-fly with local cache.

---

## Authentication — OPAQUE (RFC 9807)

Zero-knowledge password authentication. The server never sees the password in any form.

- **Registration**: Client blinds password via OPRF → server evaluates → client derives registration record (contains NO password)
- **Login**: Two-round protocol with mutual authentication — server proves it has the record, client proves it knows the password
- **Advantage over SRP/bcrypt**: Even a fully compromised server cannot mount offline dictionary attacks (OPRF-hardened)
- **Lockout**: Progressive (5/10/15+ failed attempts), checked before OPRF computation

---

## Device Security — User Entropy Seed (UES)

Dual-KEK system for fast unlock on trusted devices:

- **Slow path** (~500ms): `Argon2id(password, salt)` → KEK
- **Fast path** (~100ms): `Argon2id(password + UES, salt, lower cost)` → Device-KEK
- New devices require approval from an existing trusted device
- Each device gets a unique UES — compromise of one doesn't affect others
- UES supplements the password, never replaces it

---

## Recovery Mechanisms

### Recovery Codes
- 10 codes in `XXXX-XXXX` format, displayed once
- Stored as HMAC-SHA256 digests (timing-safe comparison)
- Recovery resets Master Key (existing files become inaccessible by design)

### Shamir Secret Sharing (K-of-N)
- Polynomial interpolation over GF(2^8)
- Share types: server-held, email, trusted contact, external (QR/paper)
- K shares reconstruct the secret; fewer than K reveal zero information
- Recovery sessions expire after 24 hours

---

## Cryptographic Constants

| Constant | Value |
|----------|-------|
| AES-256-GCM key | 32 bytes |
| AES-256-GCM IV | 12 bytes |
| AES-256-GCM tag | 16 bytes |
| Argon2id memoryCost | 47,104 KiB (46 MiB) |
| Argon2id timeCost | 1 |
| Argon2id parallelism | 1 |
| X25519 keys | 32 bytes (public + secret) |
| ML-KEM-768 public key | 1,184 bytes |
| ML-KEM-768 secret key | 2,400 bytes |
| ML-KEM-768 ciphertext | 1,088 bytes |
| Ed25519 signature | 64 bytes |
| ML-DSA-65 public key | 1,952 bytes |
| ML-DSA-65 secret key | 4,032 bytes |
| ML-DSA-65 signature | 3,309 bytes |
| Chunk size | 5 MiB (5,242,880 bytes) |
| HKDF info (files) | `"cloudvault-file-key"` |
| HKDF info (hybrid) | `"cloudvault-hybrid-file-key"` |
| HKDF info (filenames) | `"cloudvault-filename"` |

---

*This document is used by the audit triage layer (Layer 2: embedding similarity) to distinguish intentional design decisions from actual vulnerabilities. Findings that match documented patterns are classified as false positives and suppressed.*
