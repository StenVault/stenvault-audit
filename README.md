# CloudVault Audit — AI-Powered Security Audit Pipeline

An automated security audit pipeline that uses **tree-sitter AST parsing**, **cryptographic data flow tracing**, and **LLM-based analysis with 3-layer false positive triage** to find real vulnerabilities in TypeScript codebases — running entirely on local hardware.

Built to audit [CloudVault](https://github.com/Gefson-costa/cloudvault) — a zero-knowledge encrypted storage platform with post-quantum cryptography — but applicable to any codebase with security-critical code.

## Why This Exists

Cloud-based AI can audit code, but it requires sending proprietary source code to third-party servers. This pipeline runs **100% locally** using Docker + Ollama, keeping your code private while providing structured, repeatable security audits with precise file/line coordinates.

The core problem: small LLMs (7B parameters) hallucinate. They flag intentional design decisions as bugs and fabricate code that doesn't exist. This pipeline solves that with **pre-processing** (AST + data flow) and **post-processing** (3-layer triage).

## Architecture

```
TypeScript Source Code
│
├── 1. Tree-sitter AST Parser
│      Extracts functions, builds call graph, groups connected components
│      Chunks at function boundaries (never mid-function)
│
├── 2. Crypto Data Flow Tracer
│      Traces IVs, keys, salts backwards to their origin
│      Classifies: CRYPTO_RANDOM, DERIVED, PARAMETER, HARDCODED
│
├── 3. Prompt Builder
│      Combines: code chunk + data flow traces + security checklist
│      Binary yes/no questions — reduces LLM reasoning burden
│
├── 4. DeepSeek R1 Analysis (3 runs at temps 0.1, 0.3, 0.5)
│      Cross-validation: same finding in 3/3 runs = high confidence
│      Consensus scoring eliminates hallucinations
│
└── 5. Triage Pipeline (3 layers)
       ├── Layer 1: Auto-filter (rule-based)
       │   No checklist item? Line out of bounds? Evidence not in source? → Rejected
       │
       ├── Layer 2: Embedding similarity (nomic-embed-text + ChromaDB)
       │   Compare finding against design docs — if it matches a documented
       │   decision → false positive → Rejected
       │
       └── Layer 3: Whitelist (pattern matching)
           Known-good patterns with file globs → Suppressed
```

### Key Design Decisions

| Decision | Why |
|----------|-----|
| **Tree-sitter instead of regex** | Regex can't track where a function ends in nested code. For cryptography, ~90% coverage isn't enough — we need exact data flow from IV origin to encryption call |
| **Pre-computed data flow traces** | A 7B model can't reliably trace `iv → deriveChunkIV → HKDF → baseIV` across 200 lines. Pre-computing reduces the task to "is CRYPTO_RANDOM safe for an IV?" — a simple binary check |
| **3 runs with different temperatures** | Cross-validation: if 3/3 runs find the same issue, it's likely real. If only 1/3 finds it, it's likely a hallucination. Consensus scoring (1.0 / 0.67 / 0.33) provides confidence levels |
| **Embedding triage against design docs** | The LLM flags `deriveChunkIV` as "IV reuse risk". But CLAUDE.md documents this as intentional (HKDF with fileId+chunkIndex). Embedding similarity detects this match and suppresses the false positive |
| **Docker isolation** | Audit pipeline has different dependencies (tree-sitter, chromadb) than the target codebase (Node.js). Docker prevents conflicts. Codebase mounted read-only — the audit can never modify your code |
| **Ollama on host, not in Docker** | GPU passthrough to Docker on Windows requires extra setup. Simpler to connect from containers via `host.docker.internal` |

## Coverage

**15 YAML checklists, 98 security items across 9 domains:**

| Domain | Items | What it checks |
|--------|:-----:|---------------|
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

- **Docker Desktop** (running)
- **Ollama** with `deepseek-r1:7b` and `nomic-embed-text` models
- ~4GB VRAM minimum

## Quick Start

```bash
# Full audit (all 9 domains, 30-90 min)
bash run.sh full

# Single domain (5-15 min)
bash run.sh audit crypto
bash run.sh audit auth
bash run.sh audit signatures

# Combine domains
bash run.sh audit crypto auth

# Run triage on results
bash run.sh triage-init    # First time: index design docs
bash run.sh triage         # Filter false positives
```

## Output

Reports in `./reports/` as JSON:

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

**Priority:** `validated` + `critical` first, then `high`, then `medium`. Ignore `rejected` and `whitelisted`.

## Project Structure

```
cloudvault-audit/
├── run.sh                  # Main command interface
├── docker-compose.yml      # 2 containers: ast-parser + triage
├── ast-parser/             # Container 1: Audit engine
│   ├── src/parser.py       #   Tree-sitter AST extraction + call graph
│   ├── src/data_flow.py    #   Crypto variable origin tracing
│   └── src/prompt_builder.py   # Prompt formatting for DeepSeek
├── triage/                 # Container 2: False positive filter
│   ├── src/auto_filter.py  #   Layer 1: rule-based checks
│   ├── src/embedding_triage.py  # Layer 2: design doc similarity
│   └── src/whitelist.py    #   Layer 3: pattern suppression
├── checklists/             # 15 YAML files, 98 security items
├── whitelist/              # Known-good patterns to suppress
├── design-docs/            # Design documentation for triage comparison
├── dashboard/              # Web dashboard for viewing results
└── reports/                # Output: JSON audit reports
```

## Adding Custom Checklists

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

## Part of the CloudVault Ecosystem

| Project | Purpose |
|---------|---------|
| [CloudVault](https://github.com/Gefson-costa/cloudvault) | Zero-knowledge encrypted cloud storage |
| [CloudVault RAG](https://github.com/Gefson-costa/cloudvault-rag) | Navigate and query the codebase locally |
| **CloudVault Audit** (this repo) | Automated security audit pipeline with AST parsing |
