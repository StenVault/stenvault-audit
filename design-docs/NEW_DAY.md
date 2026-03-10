# NEW_DAY.md - CloudVault Zero-Knowledge Transformation

> **Objetivo**: Transformar CloudVault em verdadeiro zero-knowledge com quantum-safe encryption, OPAQUE authentication, e User Entropy Seed.

---

## EU Compliance

| Standard | Status | Notes |
|----------|--------|-------|
| ENISA ECCG ACM v2.0 | ✅ | AES-256, ML-KEM-768, ML-DSA-65 |
| BSI TR-02102-1 (Jan 2025) | ✅ | Argon2id, AES-256-GCM, ML-KEM |
| BSI/ANSSI Joint Statement (Nov 2025) | ✅ | Hybrid PQC obrigatório — X25519+ML-KEM-768 |
| EU PQC Roadmap (Jun 2025) | ✅ | Transição até 2030 — CloudVault 4 anos à frente |
| eIDAS 2.0 ZKP | 📋 Futuro | Selective disclosure (pós-2026, "not mature enough" per EUDI ARF) |
| EUCS SEAL-3+ | ✅ | Client-managed keys |

---

## Status Geral

✅ Web: **100% COMPLETO** (2026-02-09)
📋 EU Funding Features: 20-40 horas (Etapa 10 — Q3-Q4 2026)

| Etapa | Nome | Status | Data |
|-------|------|--------|------|
| **1** | Master Key (fonte única de encriptação) | ✅ | 2026-02-04 |
| **2** | Quantum-Safe (X25519 + ML-KEM-768, CVEF v1.2) | ✅ | 2026-02-04 |
| **3** | User Entropy Seed (dual-KEK, trusted devices) | ✅ | 2026-02-04 |
| **4** | Recovery System (10 codes, password reset) | ✅ | 2026-02-04 |
| **5** | Encrypted Filenames (upload, decrypt, search) | ✅ | 2026-02-04 |
| **6** | Cleanup & Docs (deep clean ~50K lines removed) | ✅ | 2026-02-09 |
| **7.1** | Decrypt-Then-Play (Web Worker >10MB) | ✅ | 2026-02-06 |
| **7.2** | Encrypted Thumbnails (client-side, HKDF) | ✅ | 2026-02-06 |
| **7.3** | ~~Streaming Decrypt~~ | ❌ Removido | deep clean `28a7bd1a` |
| **9.1** | OPAQUE Zero-Knowledge Auth (RFC 9807) | ✅ | 2026-02-09 |
| **9.3** | OPAQUE Cleanup (legacy bcrypt removed) | ✅ | 2026-02-14 |
| **10** | ZKP Selective Disclosure (zk-STARKs) | 📋 Q3-Q4 2026 | — |

---

## Etapas Completas — Resumo

### Etapa 1: Master Key ✅
Encriptação obrigatória via Master Key única. Upload usa HKDF-derived file keys (v3). Download suporta v1/v2/v3. Backend rejeita uploads não-encriptados.

### Etapa 2: Quantum-Safe ✅
Keypairs híbridos (X25519 + ML-KEM-768) gerados no setup. Arquivos novos usam CVEF v1.2 (v4). Fallback para v3 se keypair indisponível. Download suporta v1-v4.

### Etapa 3: User Entropy Seed ✅
UES (256-bit) via device entropy + HKDF. Dual-KEK: Device-KEK (~100ms fast-path) + Base-KEK (~500ms slow-path). Trusted Devices Registry com approval flow. Novo device requer aprovação ou recovery code.

### Etapa 4: Recovery System ✅
10 recovery codes (8 chars) gerados no setup, SHA-256 hashed. Password reset com recovery code (3-step flow). Regeneração de códigos em Settings.

### Etapa 5: Encrypted Filenames ✅
Nomes encriptados no upload com Master Key. Decriptação client-side com cache. Busca local em nomes decriptados. Fallback: "[Encrypted]" se decriptação falhar.

### Etapa 6: Cleanup ✅
~50,200 linhas removidas (deep clean `28a7bd1a`). AI features + video downloader removidos. `useMasterKey.ts` dividido: crypto puro → `masterKeyCrypto.ts`. DashboardLayout refactored → `AuthenticatedShell.tsx`.

### Etapa 7: Encrypted Media ✅
**7.1**: Decrypt-then-play via Web Worker (>10MB threshold). Blob URL temporário, quantum-safe key zeroing.
**7.2**: Thumbnails client-side (Canvas API, WebP, 400px max). Encriptados com HKDF-derived key, upload junto com arquivo.

### Etapa 9: OPAQUE Auth ✅
OPAQUE RFC 9807 via `@serenity-kit/opaque`. Server NUNCA vê password. Migração gradual de utilizadores existentes. Legacy bcrypt removido (2026-02-14). 9 testes E2E.

---

## Etapa 10: ZKP Selective Disclosure (FUTURO)

**Status**: 📋 Q3-Q4 2026 (após EU Funding Round 1)
**Estimativa**: 20-40 horas
**Dependências**: Etapas 1-9 completas + parceria académica

**Decisão**: zk-STARKs (quantum-safe, sem trusted setup). NÃO zk-SNARKs.

| Sub-etapa | Descrição | Estimativa |
|-----------|-----------|------------|
| 10.1 | Proof of File Integrity — zk-STARK proof de hash sem desencriptar | 8-12h |
| 10.2 | Selective Attribute Disclosure — provar propriedades sem revelar dados (eIDAS 2.0) | 8-12h |
| 10.3 | Proof of Storage — verificação criptográfica de posse (EUCS SEAL-3+) | 6-10h |

**EU Funding targets**: Horizon Europe ECCC-03/06, NGI Zero Commons Fund (até EUR 500K).
**Esperar**: NIST PEC standardização antes de implementar.

---

## Verificação Zero-Knowledge

| Propriedade | Status |
|-------------|--------|
| Servidor NUNCA vê conteúdo de arquivos | ✅ |
| Servidor NUNCA vê Master Password | ✅ |
| Servidor NUNCA vê nomes de arquivos | ✅ |
| Servidor NUNCA vê login password (OPAQUE) | ✅ |
| Todos arquivos novos usam ML-KEM-768 + X25519 | ✅ |
| ML-DSA-65 + Ed25519 para assinaturas | ✅ |
| Hybrid approach (BSI/ANSSI obrigatório) | ✅ |
| UES + device approval | ✅ |
| Recovery codes funcionam | ✅ |

---

## Backlog

- [x] ~~Chat: upgrade ECDH P-256 para hybrid PQC~~ ✅ (`ae215d8f` — X25519 + ML-KEM-768)
- [ ] Etapa 10: ZKP após standardização NIST PEC (Q3-Q4 2026)

---

*Última atualização: 2026-02-23*
