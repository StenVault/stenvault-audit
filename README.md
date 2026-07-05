# StenVault Audit

Security audit and adversarial testing pipeline for the StenVault codebase. Two modules: static analysis via LLM-assisted code review, and live adversarial testing against a running instance.

> Part of the StenVault ecosystem — [stenvault](https://github.com/Gefson-costa/stenvault) · [stenvault-rag](https://github.com/Gefson-costa/stenvault-rag)

---

## Modules

### Static Analysis (`ast-parser/` + `triage/`)

Tree-sitter AST parsing, crypto data flow tracing, DeepSeek R1 analysis with 3-layer false positive triage. Reads code, does not execute it.

### Adversarial Testing (`adversarial/`)

Deploys the full StenVault stack in Docker (application, database, cache, object storage) and attacks it with automated tooling. The application runs from its production image and is not aware it is being tested.

| Tool | Function |
|------|----------|
| Nuclei | Custom YAML templates targeting each tRPC endpoint. Auth bypass, IDOR, rate limit enforcement, injection, header validation, CORS, session manipulation. |
| Race harness | 50 concurrent requests against critical endpoints. Double registration, brute force, CSRF bypass. |
| Toxiproxy | Infrastructure failure injection. Redis kill, database latency, connection resets. Validates fail-closed behavior. |
| Fuzzer | Nuclei in continuous loop for extended duration testing. |

Both modules run in Docker. No code or traffic leaves the local machine.

---

## Static Analysis Pipeline

```
TypeScript source
│
├── 1. Tree-sitter AST parser
│      Function extraction, call graph, connected components
│      Chunks at function boundaries (never mid-function)
│
├── 2. Crypto data flow tracer
│      Traces IVs, keys, salts backwards to origin
│      Classifies: CRYPTO_RANDOM | DERIVED | PARAMETER | HARDCODED
│
├── 3. Prompt builder
│      Code chunk + data flow traces + security checklist
│      Binary yes/no questions to reduce LLM reasoning burden
│
├── 4. DeepSeek R1 analysis (3 runs at temps 0.1, 0.3, 0.5)
│      Consensus scoring: 3/3 = high confidence, 1/3 = likely hallucination
│
└── 5. Triage (3 layers)
       ├── Auto-filter: line out of bounds? evidence not in source? → rejected
       ├── Embedding similarity: matches documented design decision? → false positive
       └── Whitelist: known-good pattern with file glob match? → suppressed
```

15 YAML checklists, 98 security items across 9 domains:

| Domain | Items | Checks |
|--------|:-----:|--------|
| `crypto` | 29 | AES-GCM IVs, key derivation, ML-KEM-768 parameters |
| `signatures` | 8 | Ed25519 + ML-DSA-65 verification, key sizes |
| `key_lifecycle` | 12 | Master Key generation, wrapping, zeroing, rotation |
| `filename_enc` | 7 | Filename encryption, IV uniqueness, key derivation |
| `auth` | 17 | JWT validation, OPAQUE protocol, TOTP timing |
| `recovery` | 18 | Recovery codes, Shamir GF(2^8), Public Send crypto |
| `dataflow` | 8 | Presigned URLs, R2 storage, Redis TTLs |
| `p2p` | 5 | WebRTC signaling, ECDH key exchange |
| `validation` | 8 | Input validation, injection prevention |

---

## Adversarial Testing Results (2026-04-14)

### Summary

| Category | Tests | Passed | Failed |
|----------|------:|-------:|-------:|
| Nuclei (custom templates) | 12 | 12 | 0 |
| Race conditions | 4 | 3 | 1 |
| Chaos engineering | 6 | 6 | 0 |
| **Total** | **22** | **21** | **1** |

The single failure was caused by CSRF enforcement blocking a request before the rate limiter evaluated it. Not a vulnerability.

### Nuclei

15 custom templates across 7 categories. Each template encodes exact knowledge of the tRPC endpoint paths and input schemas.

- **Authentication**: 9 protected endpoints rejected without JWT. Forged and expired tokens rejected. MFA brute force rate limited.
- **IDOR**: Sequential file ID enumeration returns NOT_FOUND (never FORBIDDEN). No existence inference possible.
- **Rate limiting**: Login, registration, abuse report, and Shamir recovery endpoints all enforced under concurrent load.
- **Injection**: SQL injection, XSS, and path traversal payloads rejected by Zod schemas. No reflections in responses.
- **Headers**: CSP script-src has no unsafe-inline. X-Frame-Options DENY. No server version leak.
- **CORS**: Foreign origins rejected. No credential reflection.
- **Sessions**: Sensitive fields (opaqueRecord, mfaSecret, backupCodes) absent from all responses.

### Race Conditions

50 concurrent requests per test.

| Test | Result |
|------|--------|
| Double registration (same email) | 50/50 rate limited (429) |
| Login brute force | 50/50 rate limited (429) |
| CSRF bypass (no token) | 10/10 rejected (403) |

### Chaos Engineering

Infrastructure failures injected via Toxiproxy.

| Failure | Application behavior |
|---------|---------------------|
| Redis killed | Rate limiter fails closed (429). Auth endpoint responds without hanging. |
| Database +3s latency | Request completes without corruption. |
| Redis 50% packet loss | 5/5 requests recovered. |
| Database connection reset | No partial writes. Request fully rejected. |

---

## Usage

### Static analysis

```bash
# Full audit (all 9 domains)
./run.sh full

# Single domain
./run.sh audit crypto

# Triage false positives
./run.sh triage-init    # first time: index design docs
./run.sh triage
```

### Static analysis — v2 (strong local model + structured output)

The v2 paths drop chunking and 3x-temperature consensus in favor of whole-file
analysis by a strong local model (default `qwen3.5:9b`) with schema-constrained
output, followed by one adversarial self-verification pass that removes false
positives. Findings are reported with full accounting (raw / confirmed /
suppressed) and stay drop-in compatible with `./run.sh triage`.

```bash
# Path 1 — whole-file audit + verifier
./run.sh audit-v2 crypto

# Path 2 — agentic: the model investigates with read/grep/get_symbol tools
./run.sh agentic crypto

# Path 3 — audit only files changed since a git ref (default HEAD~1)
./run.sh diff-audit HEAD~5

# Compare two report JSONs (e.g. legacy vs v2)
./run.sh compare crypto_20260101_120000.json whole_file_20260705_120000.json
```

Config (env): `AUDIT_MODEL`, `VERIFIER_MODEL` (default `qwen3.5:9b`),
`AUDIT_THINK` (`false`), `AUDIT_NUM_CTX` (`16384`), `AGENT_MAX_STEPS` (`8`),
`DIFF_AGENTIC` (`false`). All local-first; no code leaves the machine.

### Adversarial testing

```bash
# Full attack suite (Nuclei + race tester)
./run.sh adversarial

# Chaos engineering only
./run.sh adversarial-chaos

# Continuous fuzzing (default 300s)
./run.sh adversarial-fuzz 600

# Start stack for manual testing
./run.sh adversarial-up

# Cleanup
./run.sh adversarial-down
```

### Dashboard

```bash
./run.sh dashboard    # http://localhost:7800
```

---

## Requirements

### Static analysis
- Docker Desktop
- Ollama with `deepseek-r1:7b` and `nomic-embed-text`
- ~4GB VRAM minimum

### Adversarial testing
- Docker Desktop
- ~4GB RAM for the full stack
- No GPU required

Ollama runs on the host. The codebase is mounted read-only. No code or test data leaves the machine.

---

## Structure

```
stenvault-audit/
├── run.sh                          Entry point (all commands)
├── docker-compose.yml              Static analysis containers
├── ast-parser/                     Tree-sitter + data flow + prompt builder
├── triage/                         Auto-filter + embedding + whitelist
├── checklists/                     15 YAML security checklists (98 items)
├── whitelist/                      Known-good patterns
├── design-docs/                    Design documentation for triage context
├── dashboard/                      Web UI for viewing results
├── reports/                        Static analysis JSON output
└── adversarial/
    ├── docker-compose.yml          Full stack + attack containers
    ├── nuclei-templates/           15 custom YAML templates (7 categories)
    │   ├── auth/                   Auth bypass, MFA, Shamir probing
    │   ├── idor/                   Cross-user access, ID enumeration
    │   ├── rate-limit/             Login, register, abuse brute force
    │   ├── injection/              SQLi, XSS, path traversal, send fuzzing
    │   ├── crypto/                 Version downgrade, plaintext rejection
    │   ├── session/                JWT manipulation, SSE probing
    │   └── headers/                CSP, CORS, cookie flags
    ├── seed/                       Test data seeder
    ├── race-tester/                Concurrent request harness
    ├── chaos-tester/               Toxiproxy failure injection
    └── reports/                    Adversarial test output
```

---

## Custom templates

```yaml
id: stenvault-my-test
info:
  name: Description of what this tests
  severity: high
  tags: category

http:
  - method: POST
    path:
      - "{{BaseURL}}/api/trpc/router.procedure"
    body: '{"json":{"field":"{{payload}}"}}'
    payloads:
      payload:
        - "malicious-value"
    matchers:
      - type: word
        words:
          - "should-not-appear"
        negative: true
```

Add YAML files to `adversarial/nuclei-templates/<category>/`. They execute automatically on the next `./run.sh adversarial`.

---

## Ecosystem

| Project | Purpose |
|---------|---------|
| [StenVault](https://github.com/Gefson-costa/stenvault) | Zero-knowledge encrypted cloud storage |
| [StenVault RAG](https://github.com/Gefson-costa/stenvault-rag) | Local codebase search and Q&A |
| **StenVault Audit** (this repo) | Security audit and adversarial testing pipeline |
