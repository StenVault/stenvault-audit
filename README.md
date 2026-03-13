# StenVault Audit

Local AI security audit pipeline for cryptographic codebases. Tree-sitter AST parsing, crypto data flow tracing, DeepSeek R1 analysis with 3-layer false positive triage. Runs in Docker, no code leaves your machine.

> Part of the StenVault ecosystem — [stenvault](https://github.com/Gefson-costa/stenvault) · [stenvault-rag](https://github.com/Gefson-costa/stenvault-rag)

## Problem

Small LLMs (7B parameters) hallucinate when auditing code. They flag intentional design decisions as bugs and fabricate code that doesn't exist. Raw LLM output on a cryptographic codebase is mostly noise.

This pipeline fixes that with pre-processing (AST extraction + crypto data flow tracing) and post-processing (3-layer triage). The LLM receives structured context instead of raw source, and its output goes through automated validation before reaching you.

## Pipeline

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
       ├── Auto-filter: no checklist item? line out of bounds? evidence not in source? → rejected
       ├── Embedding similarity: finding matches documented design decision? → false positive
       └── Whitelist: known-good pattern with file glob match? → suppressed
```

## Why tree-sitter instead of regex

Regex can't reliably track where a function ends in nested code. For cryptography, approximate coverage isn't useful — you need exact data flow from IV origin to encryption call. Tree-sitter gives you a real AST.

The data flow tracer pre-computes paths like `iv → deriveChunkIV → HKDF → baseIV` so the LLM doesn't have to. A 7B model can't reliably trace variable origins across 200 lines. But it can answer "is CRYPTO_RANDOM safe for an IV?" — that's a binary check it handles well.

## Why 3 runs at different temperatures

Cross-validation. If all 3 runs flag the same issue, it's probably real. If only 1 of 3 finds it, it's probably a hallucination. Consensus scores (1.0 / 0.67 / 0.33) give you confidence levels to prioritize triage.

## Why embedding triage

The LLM flags `deriveChunkIV` as "IV reuse risk". But the design docs describe this as intentional — HKDF with fileId + chunkIndex as context. Embedding similarity between the finding and the design docs catches this and suppresses the false positive automatically.

## Coverage

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

## Requirements

- Docker Desktop (running)
- Ollama with `deepseek-r1:7b` and `nomic-embed-text`
- ~4GB VRAM minimum

Ollama runs on the host, not in Docker. GPU passthrough to Docker on Windows requires extra setup; connecting via `host.docker.internal` is simpler. The codebase is mounted read-only — the audit cannot modify your code.

## Usage

```bash
# Full audit (all 9 domains, 30-90 min)
bash run.sh full

# Single domain
bash run.sh audit crypto
bash run.sh audit auth

# Multiple domains
bash run.sh audit crypto auth

# Triage
bash run.sh triage-init    # first time: index design docs
bash run.sh triage         # filter false positives
```

## Output

JSON reports in `./reports/`:

```json
{
  "file": "apps/web/src/lib/fileCrypto.ts",
  "line_start": 142,
  "line_end": 158,
  "severity": "high",
  "checklist_item": "C09",
  "finding": "Chunks can be reordered without detection",
  "evidence": "const encrypted = await crypto.subtle.encrypt(...)",
  "suggestion": "Bind chunk index to AAD parameter",
  "consensus": 1.0,
  "triage_status": "validated"
}
```

Prioritize `validated` + `critical` first. Ignore `rejected` and `whitelisted`.

## Structure

```
stenvault-audit/
├── run.sh                          Entry point
├── docker-compose.yml              2 containers: ast-parser + triage
├── ast-parser/
│   ├── src/parser.py               Tree-sitter AST extraction + call graph
│   ├── src/data_flow.py            Crypto variable origin tracing
│   └── src/prompt_builder.py       Prompt formatting
├── triage/
│   ├── src/auto_filter.py          Layer 1: rule-based rejection
│   ├── src/embedding_triage.py     Layer 2: design doc similarity
│   └── src/whitelist.py            Layer 3: pattern suppression
├── checklists/                     15 YAML files, 98 security items
├── whitelist/                      Known-good patterns
├── design-docs/                    Design documentation for triage
├── dashboard/                      Web UI for viewing results
└── reports/                        JSON output
```

## Custom checklists

```yaml
# checklists/my_domain.yaml
checklist_id: my_custom_check
stage: crypto
items:
  - id: C99
    question: "Is the key at least 256 bits?"
    severity: critical
```

Rebuild and run: `bash run.sh build && bash run.sh audit crypto`

## Ecosystem

| Project | Purpose |
|---------|---------|
| [StenVault](https://github.com/Gefson-costa/stenvault) | Zero-knowledge encrypted cloud storage (open-source client) |
| [StenVault RAG](https://github.com/Gefson-costa/stenvault-rag) | Local codebase search and Q&A |
| **StenVault Audit** (this repo) | Automated security audit pipeline |
