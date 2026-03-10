# CloudVault Sovereign Transformation Roadmap

**Last Updated**: 2026-02-23

Multi-phase upgrade to CloudVault's cryptography: quantum-safe encryption, master key wrapping, blockchain timestamps, crypto agility, and HSM support.

---

## Phase Overview

| Phase | Name | Status | Summary |
|-------|------|--------|---------|
| **P0** | Foundation | ✅ Complete | Argon2id KDF, AES-KW master key wrapping, CVEF v1.1 |
| **P1** | PQC Encryption | ✅ Complete | X25519 + ML-KEM-768 hybrid KEM, CVEF v1.2 |
| **P2** | Blockchain Timestamps | ✅ Complete | OpenTimestamps (Bitcoin-backed proof of existence) |
| **P2.5/2.6** | Timestamp UI + Legal PDF | ✅ Complete | Badge UI, details dialog, court-admissible PDF export |
| **P3.1** | Key Recovery | ✅ Complete | Shamir Secret Sharing (K-of-N threshold) |
| **P3.2** | HSM Support | ✅ Architecture | Pluggable providers (software + HashiCorp Vault ready) |
| **P3.4** | PQ Signatures | ✅ Complete | Ed25519 + ML-DSA-65 hybrid (upload signing + download verification) |

---

## Relationship to NEW_DAY.md

| NEW_DAY Etapa | SOVEREIGN Phase | Status |
|---------------|----------------|--------|
| Etapa 1 | P0.2 (Master Key) | ✅ |
| Etapa 2 | P1 (ML-KEM-768) | ✅ |
| Etapa 3 | UES (device-bound) | ✅ |
| Etapa 4 | P3.1 (recovery) | ✅ |
| Etapa 5 | Zero-knowledge filenames | ✅ |
| Etapa 6 | Cleanup | ✅ |
| Etapa 7 | Encrypted media playback | 📋 Next |
| Etapa 8 | Plausible deniability | 📋 Q3-Q4 2026 |

---

## Phase 0: Foundation

**Status**: ✅ Complete (2026-01-31)

| Task | Description |
|------|-------------|
| P0.1 | Argon2id KDF (OWASP 2024: 47 MiB, t=1, p=1) |
| P0.2 | Master Key Wrapping (AES-KW RFC 3394) |
| P0.3 | CVEF v1.1 file format (algorithm IDs, crypto agility) |
| P0.4 | liboqs POC (ML-KEM-768 WASM) |
| P0.5 | Migration infrastructure (PBKDF2 → Argon2id) |
| P0.6 | Device identity foundation |

**Key derivation**: Password → Argon2id → KEK → AES-KW Unwrap → Master Key → AES-256-GCM → Encrypted File

**Key files**:
- `packages/shared/src/platform/crypto/argon2.ts` — Argon2id interface
- `packages/shared/src/platform/crypto/keyWrap.ts` — AES-KW interface
- `packages/shared/src/platform/crypto/cvef.ts` — CVEF spec
- `apps/web/src/lib/platform/webArgon2Provider.ts` — Web Argon2id (WASM)
- `apps/web/src/lib/platform/webKeyWrapProvider.ts` — Web AES-KW
- `apps/api/drizzle/0001_phase0_sovereign_encryption.sql` — DB migration

**DB tables**: `encryptionMigrations`, `userDevices`

---

## Phase 1: Post-Quantum Hybrid Encryption

**Status**: ✅ Complete (2026-01-31)

X25519 (classical) + ML-KEM-768 (post-quantum) → HKDF → Hybrid KEK → AES-KW wrapped file key. Defense in depth: if either algorithm is broken, the other still protects.

| Task | Description |
|------|-------------|
| P1.1–P1.3 | Hybrid KEM interface + CVEF v1.2 + Web provider |
| P1.4 | Hybrid file encryption (`hybridFileCrypto.ts`) |
| P1.5–P1.6 | DB schema + server-side router (7 endpoints) |
| P1.7–P1.9 | Migration, type declarations, tests (65 tests) |

**Key files**:
- `packages/shared/src/platform/crypto/hybridKem.ts` — Interface, types, validation
- `apps/web/src/lib/platform/webHybridKemProvider.ts` — X25519 + ML-KEM-768 WASM
- `apps/web/src/lib/hybridFileCrypto.ts` — Hybrid encrypt/decrypt
- `apps/api/src/_core/hybridKemRouter.ts` — 7 tRPC procedures
- `apps/api/drizzle/0002_phase1_hybrid_kem.sql` — DB migration

**DB table**: `userHybridKeyPairs`

**Fallback**: Clients without WASM use server-side encapsulation via `hybridKem.serverSideEncapsulate`.

---

## Phase 2: Blockchain Timestamps

**Status**: ✅ Complete (2026-01-31)

OpenTimestamps (Bitcoin-backed) proof of file existence. Zero-knowledge: timestamps the **encrypted ciphertext hash**, never plaintext.

| Task | Description |
|------|-------------|
| P2.1–P2.3 | OTS client, DB schema, timestamp router (7 procedures) |
| P2.4 | Background job for proof upgrades |
| P2.5 | UI: badges in FileGrid/FileTable/Mobile, details dialog |
| P2.6 | Legal PDF export (court-admissible certificates) |

**Key files**:
- `apps/api/src/_core/timestamp/otsClient.ts` — OTS client (submit, upgrade, verify)
- `apps/api/src/_core/timestampRouter.ts` — 7 tRPC procedures + `generateLegalPdf`
- `apps/api/src/_core/timestamp/legalPdfGenerator.ts` — PDF generation
- `apps/api/src/_core/jobs/upgradeTimestamps.ts` — Background job (run every 30min)
- `apps/web/src/components/files/components/TimestampBadge.tsx` — Badge UI
- `apps/web/src/components/files/components/TimestampDetails.tsx` — Details dialog
- `apps/api/drizzle/0003_phase2_timestamps.sql` — DB migration

**DB table**: `fileTimestamps`

**Env vars**: `OTS_ENABLED=true`, `OTS_CALENDAR_URLS=https://a.pool.opentimestamps.org,https://b.pool.opentimestamps.org`

---

## Phase 3.1: Shamir Secret Sharing

**Status**: ✅ Complete (2026-02-03)

K-of-N threshold recovery for master key. Share types: Server, Email, Trusted Contact, External (QR/Paper). AES-256-GCM encrypted shares, HMAC-SHA256 integrity, 24h session expiry, rate limiting.

| Task | Description |
|------|-------------|
| P3.1.1–P3.1.3 | DB schema, modular tRPC router, share encryption |
| P3.1.4–P3.1.5 | Web provider + shared interface |
| P3.1.6 | Password change invalidation hook |
| P3.1.7–P3.1.8 | Setup UI + recovery page |

**Key files**:
- `apps/api/src/_core/shamirRecovery/` — Modular router (config, shares, recovery procedures)
- `apps/api/src/_core/shamirRecovery/encryption.ts` — Share encryption utils
- `packages/shared/src/platform/crypto/shamirRecovery.ts` — Platform interface
- `apps/web/src/lib/platform/webShamirRecoveryProvider.ts` — Web implementation
- `apps/web/src/lib/shamirSecretSharing.ts` — GF(2^8) math
- `apps/web/src/components/settings/ShamirRecoverySection.tsx` — Setup UI
- `apps/web/src/pages/ShamirRecovery.tsx` — Recovery page
- `apps/api/drizzle/0012_shamir_recovery.sql` — DB migration

**DB tables**: `shamirRecoveryConfigs`, `shamirRecoveryShares`, `shamirRecoveryAttempts`

**Router**: 11 procedures (getStatus, setupRecovery, revokeAll, initiateRecovery, submitShare, completeRecovery, etc.)

---

## Phase 3.2: HSM Support

**Status**: ✅ Architecture Complete

Pluggable HSM integration layer. Customers bring their own HSM and pay their provider directly.

**Ready providers**: `software` (dev only), `hashicorp-vault` (production)

**On-demand providers** (~40-60h each): Scaleway KMS, OVHcloud KMS, AWS CloudHSM, Azure Key Vault, Utimaco HSM, YubiHSM 2. Any provider can be added via the `HSMProvider` interface.

**Key files**:
- `packages/shared/src/platform/hsm/types.ts` — Type definitions
- `apps/api/src/_core/hsm/hsmManager.ts` — Singleton manager
- `apps/api/src/_core/hsm/providers/factory.ts` — Provider factory
- `apps/api/src/_core/hsm/` — tRPC router (admin, audit, keys)
- `apps/api/drizzle/0014_hsm_support.sql` — DB migration

---

## Phase 3.4: Post-Quantum Signatures

**Status**: ✅ Complete (2026-02-03)

Ed25519 (classical) + ML-DSA-65 (post-quantum) hybrid signatures. Files are signed on upload, verified on download.

| Task | Description |
|------|-------------|
| P3.4.1–P3.4.4 | Interface, type declarations, DB schema, SQL migration |
| P3.4.5–P3.4.6 | Web provider + server router (8 procedures) |
| P3.4.7–P3.4.8 | CVEF v1.3 format + HSM key protection constant |
| P3.4.10–P3.4.12 | signedFileCrypto, useSignatureKeys hook, useMasterKey hook |
| P3.4.13–P3.4.16 | Upload SigningPanel, download verification, SignatureBadge UI |

**Remaining (optional)**: Settings page for signature key management (LOW priority)

**Key files**:
- `packages/shared/src/platform/crypto/hybridSignature.ts` — Interface, types, validation
- `apps/web/src/lib/platform/webHybridSignatureProvider.ts` — Ed25519 + ML-DSA-65 WASM
- `apps/web/src/lib/signedFileCrypto.ts` — File signing/verification (32 tests)
- `apps/api/src/_core/hybridSignatureRouter.ts` — 8 tRPC procedures
- `apps/web/src/hooks/useSignatureKeys.ts` — Key management hook
- `apps/web/src/components/FileUploader/components/SigningPanel.tsx` — Signing toggle UI
- `apps/web/src/components/FilePreviewModal/components/SignatureBadge.tsx` — Verification badge
- `apps/api/drizzle/0019_phase3_signatures.sql` — DB migration

**DB tables**: `userSignatureKeyPairs`, `fileSignatures`

---

## Cryptographic Algorithms Summary

| Purpose | Algorithm |
|---------|-----------|
| KDF | Argon2id (47 MiB, t=1, p=1) |
| Key Wrap | AES-KW (RFC 3394) |
| File Encryption | AES-256-GCM |
| Key Exchange | X25519 + ML-KEM-768 (hybrid) |
| Signatures | Ed25519 + ML-DSA-65 (hybrid) |
| Timestamps | SHA-256 + Bitcoin (OpenTimestamps) |
| Share Encryption | AES-256-GCM + HMAC-SHA256 |

---

## Intentional Design Decisions

| Pattern | Reason |
|---------|--------|
| `.startsWith()` for HMAC in `decodeExternalShare` | QR codes truncate data, prefix match is intentional |
| 32-char HMAC (not 64) | 128-bit security is sufficient, 64 chars breaks QR codes |
| Software HSM as dev default | Production requires explicit `HSM_PROVIDER` env var |
