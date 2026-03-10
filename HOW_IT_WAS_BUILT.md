# How This Audit Pipeline Was Built — Step by Step

> This document explains everything that was done to build this pipeline from scratch.
> If you want to rebuild it yourself or understand every piece, read this top to bottom.

---

## Table of Contents

1. [The Idea](#1-the-idea)
2. [Prerequisites](#2-prerequisites)
3. [Docker Basics You Need to Know](#3-docker-basics-you-need-to-know)
4. [Project Structure](#4-project-structure)
5. [Step 1 — Docker Configuration](#5-step-1--docker-configuration)
6. [Step 2 — Tree-sitter AST Parser](#6-step-2--tree-sitter-ast-parser)
7. [Step 3 — Crypto Data Flow Tracing](#7-step-3--crypto-data-flow-tracing)
8. [Step 4 — Prompt Builder](#8-step-4--prompt-builder)
9. [Step 5 — Orchestrator](#9-step-5--orchestrator)
10. [Step 6 — Triage Pipeline](#10-step-6--triage-pipeline)
11. [Step 7 — Checklists and Whitelists](#11-step-7--checklists-and-whitelists)
12. [Step 8 — Connecting Everything](#12-step-8--connecting-everything)
13. [How the Data Flows](#13-how-the-data-flows)
14. [Key Decisions and Why](#14-key-decisions-and-why)

---

## 1. The Idea

The problem: CloudVault has complex cryptography (AES-256-GCM, Argon2id, X25519+ML-KEM-768, Ed25519+ML-DSA-65, OPAQUE, Shamir, etc.). A local AI model (DeepSeek R1 7B) can audit this code for security issues, but it has limitations:

- **Small context window** (8K tokens) — can't read an entire file at once
- **Limited reasoning** — can do pattern matching but struggles with complex logic
- **Generates false positives** — flags intentional designs as problems

The solution: a pipeline that **pre-processes** the code so the AI only needs to answer simple yes/no questions.

```
Code → Tree-sitter parses it → Chunks are created → Crypto traces are computed
    → DeepSeek checks a binary checklist → Triage filters false positives
    → Final report with precise coordinates
```

---

## 2. Prerequisites

What you need installed on your machine:

| Tool | What it does | How to install |
|------|-------------|----------------|
| **Docker Desktop** | Runs isolated containers (like lightweight VMs) | https://www.docker.com/products/docker-desktop/ |
| **Ollama** | Runs AI models locally on your GPU | https://ollama.com/download |
| **DeepSeek R1 7B** | The AI model that does the audit | `ollama pull deepseek-r1:7b` |
| **nomic-embed-text** | Embedding model for triage | `ollama pull nomic-embed-text` |
| **Git Bash** | Unix shell on Windows (for run.sh) | Comes with Git for Windows |

### Verify everything is working

```bash
# Docker is running?
docker --version
# Should print: Docker version 28.x.x

# Ollama is running?
curl http://localhost:11434
# Should print: Ollama is running

# Models are available?
ollama list
# Should show deepseek-r1:7b and nomic-embed-text
```

---

## 3. Docker Basics You Need to Know

Docker runs your code in **containers** — isolated environments with their own file system, Python version, and libraries. Think of it as a lightweight virtual machine.

### Key concepts

**Image** = A blueprint (like a class in programming). Built from a `Dockerfile`.
```
Dockerfile → docker build → Image
```

**Container** = A running instance of an image (like an object from a class).
```
Image → docker run → Container (running process)
```

**Volume** = A shared folder between your computer and the container.
```
Your PC: D:\Projects\Cloud\vault  ←→  Container: /codebase
Your PC: ./reports                ←→  Container: /reports
```

**docker-compose.yml** = A file that defines multiple containers and how they connect.

### Commands you'll use

```bash
# Build images from Dockerfiles
docker compose build

# Run a container (and delete it when done)
docker compose run --rm ast-parser crypto

# See running containers
docker ps

# See logs of a running container
docker logs -f audit-ast-parser

# Stop all containers
docker compose down

# Delete everything and start fresh
docker compose down --rmi all --volumes
```

### What happens when you run `docker compose run --rm ast-parser crypto`:

1. Docker reads `docker-compose.yml`
2. Finds the `ast-parser` service definition
3. Builds the image from `ast-parser/Dockerfile` (if not already built)
4. Creates a container from that image
5. Mounts the volumes (your codebase, checklists, reports)
6. Sets environment variables (OLLAMA_URL, MODEL, etc.)
7. Runs `python entrypoint.py crypto` inside the container
8. The container connects to Ollama on your host via `host.docker.internal:11434`
9. When the script finishes, `--rm` deletes the container (but reports are saved in the volume)

---

## 4. Project Structure

```
D:\Projects\local-audit/
│
├── docker-compose.yml          ← Defines the 2 containers and their connections
├── run.sh                      ← Convenience script (calls docker compose commands)
│
├── ast-parser/                 ← CONTAINER 1: Audit Engine
│   ├── Dockerfile              ← How to build this container's image
│   ├── requirements.txt        ← Python packages needed
│   ├── entrypoint.py           ← Main script that runs when container starts
│   └── src/
│       ├── parser.py           ← Tree-sitter: reads code, finds functions, groups them
│       ├── data_flow.py        ← Traces where IVs, keys, salts come from
│       └── prompt_builder.py   ← Formats everything into a prompt for DeepSeek
│
├── triage/                     ← CONTAINER 2: False Positive Filter
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── entrypoint.py           ← Main triage script
│   └── src/
│       ├── auto_filter.py      ← Layer 1: rule-based checks
│       ├── embedding_triage.py ← Layer 2: compares with design docs using AI
│       └── whitelist.py        ← Layer 3: known-good pattern suppression
│
├── checklists/                 ← 15 YAML files with 98 security questions
├── whitelist/                  ← JSON files with patterns to ignore
├── design-docs/                ← Copies of CLAUDE.md, etc.
├── reports/                    ← OUTPUT: JSON reports with findings
├── triage-db/                  ← ChromaDB vector database (auto-created)
└── models/                     ← Future: trained ML classifier
```

---

## 5. Step 1 — Docker Configuration

### 5.1 — docker-compose.yml

This file tells Docker: "I want 2 containers, here's how to build them, what folders to share, and what environment variables to set."

```yaml
services:
  ast-parser:                                    # Container name
    build:
      context: ./ast-parser                      # Build from this folder
      dockerfile: Dockerfile                     # Using this Dockerfile
    container_name: audit-ast-parser
    volumes:
      - /d/Projects/Cloud/vault:/codebase:ro     # Mount your code (read-only!)
      - ./checklists:/checklists:ro              # Mount checklists
      - ./reports:/reports                        # Mount reports (read-write for output)
    environment:
      - OLLAMA_URL=http://host.docker.internal:11434   # Connect to host Ollama
      - MODEL=deepseek-r1:7b
    extra_hosts:
      - "host.docker.internal:host-gateway"      # Allows container to reach host

  triage:
    build:
      context: ./triage
      dockerfile: Dockerfile
    # ... similar structure
```

**Key points:**
- `:ro` = read-only mount. The container CAN'T modify your CloudVault code.
- `host.docker.internal` = special DNS name that resolves to your host machine from inside Docker.
- `host-gateway` = tells Docker to route `host.docker.internal` to your actual machine's IP.

### 5.2 — Dockerfile (ast-parser)

This tells Docker how to build the container image:

```dockerfile
FROM python:3.12-slim           # Start from official Python 3.12 image (small)

WORKDIR /app                    # Set working directory inside container

COPY requirements.txt .         # Copy requirements file
RUN pip install --no-cache-dir -r requirements.txt   # Install Python packages

COPY src/ /app/src/             # Copy our source code
COPY entrypoint.py /app/        # Copy the main script

ENTRYPOINT ["python", "entrypoint.py"]   # This runs when the container starts
```

**Why `python:3.12-slim`?** The `slim` variant is ~150MB instead of ~900MB. It has Python but not extra tools we don't need.

### 5.3 — requirements.txt (ast-parser)

```
tree-sitter==0.24.0               # AST parser library
tree-sitter-typescript==0.23.2    # TypeScript grammar for tree-sitter
pyyaml>=6.0                       # Read YAML checklist files
requests>=2.31                    # HTTP calls to Ollama API
rich>=13.0                        # Pretty terminal output (colors, tables)
```

### Why Ollama is NOT inside Docker

We considered putting Ollama in a Docker container too, but:
- Ollama is already running on your host with GPU access
- GPU passthrough to Docker on Windows requires NVIDIA Container Toolkit setup
- It's simpler and faster to just connect to `host.docker.internal:11434`
- No duplicate model downloads (Ollama on host already has the models)

---

## 6. Step 2 — Tree-sitter AST Parser

### What is tree-sitter?

Tree-sitter is a parser that reads source code and produces an **Abstract Syntax Tree** (AST). Unlike regex, it understands the code structure.

Example — this TypeScript:
```typescript
export async function encryptFileChunk(chunk: Uint8Array, key: CryptoKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, chunk)
  return encrypted
}
```

Becomes this tree:
```
export_statement
  function_declaration
    name: "encryptFileChunk"
    parameters:
      param: "chunk" (type: Uint8Array)
      param: "key" (type: CryptoKey)
    body:
      variable_declaration: iv = call(crypto.getRandomValues, new Uint8Array(12))
      variable_declaration: encrypted = call(crypto.subtle.encrypt, {name:'AES-GCM',iv}, key, chunk)
      return_statement: encrypted
```

### Why tree-sitter instead of regex?

Regex: `function\s+(\w+)` finds function names but:
- Can't tell where a function ENDS (misses closing braces in nested code)
- Can't follow which variable goes into which function call
- Breaks on multi-line expressions
- 90% coverage isn't enough for cryptography

Tree-sitter: gives us exact start/end lines, parameter types, call graph, and data flow.

### parser.py — What it does

**Step A: Extract all functions from a file**

```python
def extract_functions(root, source) -> list[FunctionInfo]:
```

Walks the AST tree and finds every:
- `function declaration` → `function encryptChunk() {}`
- `arrow function` → `const encryptChunk = () => {}`
- `class method` → `class Crypto { encrypt() {} }`
- `export statement` → `export function encryptChunk() {}`

For each function, it records: name, start line, end line, parameters, source code.

**Step B: Build a call graph**

```python
def build_call_graph(functions, source) -> dict[str, set[str]]:
```

For each function, finds which other functions it calls. Example:
```
encryptFileChunk → calls → deriveChunkIV, buildEncryptedBuffer
decryptFileChunk → calls → deriveChunkIV
```

**Step C: Group connected functions**

```python
def find_connected_components(graph) -> list[set[str]]:
```

Functions that call each other are grouped together. This way, `encryptFileChunk` and `deriveChunkIV` end up in the **same chunk** — the AI sees the full context.

**Step D: Create chunks**

```python
def chunk_file(file_path, max_lines=200) -> list[Chunk]:
```

Groups connected functions into chunks of max 200 lines. If a group is too big, splits at function boundaries — **never in the middle of a function**.

Each chunk contains:
- File path
- Line start/end
- Function names in this chunk
- The actual source code
- List of crypto API calls found

---

## 7. Step 3 — Crypto Data Flow Tracing

### data_flow.py — What it does

For every cryptographic operation (encrypt, decrypt, deriveKey, etc.), traces **backwards** to find where the inputs come from.

Example:
```typescript
const iv = crypto.getRandomValues(new Uint8Array(12))     // line 45
const key = await crypto.subtle.importKey('raw', rawKey)   // line 46
const enc = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, data)  // line 47
```

The tracer produces:
```
encrypt @ line 47:
  algorithm: AES-GCM
  iv: CRYPTO_RANDOM via crypto.getRandomValues [line 45]
  key: IMPORTED_KEY via crypto.subtle.importKey [line 46]
```

**Why this matters**: The DeepSeek 7B model struggles to trace variable origins on its own. By pre-computing this, we reduce the task to: "is CRYPTO_RANDOM a safe origin for an IV?" — which is a simple yes/no.

### Variable origin types

| Origin | Meaning | Safe for IV? | Safe for Key? |
|--------|---------|-------------|---------------|
| `crypto_random` | `crypto.getRandomValues()` or `generateKey()` | Yes | Yes |
| `derived` | HKDF, deriveBits, deriveChunkIV | Depends on inputs | Yes |
| `parameter` | Passed in from caller | Unknown (need to check caller) | Unknown |
| `hardcoded` | String literal or number | NO | NO |
| `imported_key` | `crypto.subtle.importKey()` | N/A | Depends on source |
| `computed` | Some other function call | Need investigation | Need investigation |

---

## 8. Step 4 — Prompt Builder

### prompt_builder.py — What it does

Takes a chunk + its crypto traces + the relevant checklist and formats them into a prompt for DeepSeek.

The prompt has 4 sections:

**1. Context header**
```
FILE: apps/web/src/lib/fileCrypto.ts
CHUNK: 3/7 (lines 245-398)
FUNCTIONS: encryptFileChunk, deriveChunkIV
```

**2. Pre-computed crypto traces**
```
CRYPTO DATA FLOW TRACES:
  1. encrypt @ line 260:
     algorithm: AES-GCM
     iv: DERIVED via deriveChunkIV [line 248]
     key: PARAMETER [line 245]
```

**3. The actual code with line numbers**
```
 245 | export async function encryptFileChunk(chunk, key, chunkIndex) {
 246 |   const baseIV = crypto.getRandomValues(new Uint8Array(12))
 ...
```

**4. Checklist items**
```
CHECKLIST:
  C01 [CRITICAL]: Is every IV generated using crypto.getRandomValues() or derived via HKDF?
  C02 [CRITICAL]: Is every IV exactly 12 bytes (96 bits) for AES-GCM?
  ...
```

**5. Output format instructions**
```
Respond ONLY with a JSON array of violations. Empty array [] if no violations.
```

The key design: we tell the model exactly what format to respond in, give it pre-computed traces so it doesn't need to reason about data flow, and limit it to binary yes/no checks.

---

## 9. Step 5 — Orchestrator

### entrypoint.py — What it does

This is the main script that ties everything together. When you run `bash run.sh audit crypto`, it:

**1. Connects to Ollama**
```python
requests.get(f"{OLLAMA_URL}/api/tags")  # Verify Ollama is reachable
```

**2. For each stage, resolves file globs**
```python
STAGES = {
    "crypto": [
        "apps/web/src/lib/fileCrypto.ts",
        "apps/web/src/lib/hybridFileCrypto.ts",
        ...
    ]
}
files = list(CODEBASE.glob(pattern))  # Find actual files
```

**3. For each file, chunks it with tree-sitter**
```python
chunks = chunk_file(str(file_path), max_lines=200)
```

**4. For each chunk, traces crypto data flow**
```python
traces = trace_crypto_data_flow(chunk.content, chunk.line_start, file_path)
```

**5. Builds the prompt and sends to DeepSeek 3 times**
```python
for temp in [0.1, 0.3, 0.5]:
    raw = query_deepseek(prompt, temperature=temp)
    findings = parse_findings(raw)
```

Why 3 times? **Cross-validation**. Different temperatures make the model respond slightly differently. If 3/3 runs find the same issue, confidence is high. If only 1/3 finds it, it's probably a hallucination.

**6. Merges findings with consensus scores**
```python
finding["consensus"] = runs_that_agreed / total_runs  # 1.0, 0.67, or 0.33
```

**7. Writes JSON report to ./reports/**

### How it talks to Ollama

```python
response = requests.post(
    f"{OLLAMA_URL}/api/generate",
    json={
        "model": "deepseek-r1:7b",
        "prompt": prompt,           # The full prompt we built
        "temperature": 0.1,         # Low = more deterministic
        "stream": False,            # Wait for full response
        "options": {
            "num_ctx": 8192,        # Context window (tokens)
            "num_predict": 2048,    # Max response length
        },
    },
    timeout=600,                    # 10 minute timeout per chunk
)
```

This is a simple HTTP POST to the Ollama REST API. Ollama runs the model on your GPU and returns the text response.

### DeepSeek R1 thinking tags

DeepSeek R1 wraps its reasoning in `<think>...</think>` tags before giving the answer. Our parser strips these:
```python
think_end = response.rfind("</think>")
if think_end >= 0:
    response = response[think_end + len("</think>"):].strip()
```

---

## 10. Step 6 — Triage Pipeline

After the audit generates raw findings, the triage pipeline filters out false positives through 3 layers.

### Layer 1: Auto-filter (auto_filter.py)

Rule-based checks that don't need AI:

| Rule | What it catches |
|------|----------------|
| No checklist_item | Model invented a finding not in our checklist |
| Line out of bounds | Model referenced a line that doesn't exist in the file |
| Evidence not in source | Model fabricated code that isn't actually there |
| Duplicate | Same finding reported multiple times |
| Low consensus | Only 1 out of 3 runs found this (likely hallucination) |

### Layer 2: Embedding similarity (embedding_triage.py)

Uses the `nomic-embed-text` model to compare findings against our design documentation (CLAUDE.md, NEW_DAY.md, SOVEREIGN_ROADMAP.md).

**How it works:**

1. **Index design docs** (one-time setup):
   - Reads CLAUDE.md and other docs
   - Splits into sections
   - Generates an embedding vector for each section using nomic-embed-text
   - Stores in ChromaDB (a vector database)

2. **For each finding:**
   - Generates an embedding of the finding text
   - Searches ChromaDB for the most similar design doc section
   - If similarity is very high (distance < 0.35), the finding matches a documented design decision
   - → Rejected as false positive

Example: Finding says "IV reuse risk in deriveChunkIV". Design doc says "deriveChunkIV uses HKDF with fileId+chunkIndex — IV uniqueness guaranteed by design". These are semantically similar → finding rejected.

**What is an embedding?** It's a list of numbers (a vector) that represents the meaning of text. Similar meanings have similar vectors. `nomic-embed-text` produces 768-dimensional vectors.

**What is ChromaDB?** A database optimized for searching by vector similarity. You give it a vector, it returns the most similar stored vectors.

### Layer 3: Whitelist (whitelist.py)

Pattern-based suppression for known-good code patterns:

```json
{
  "pattern": "deriveChunkIV",
  "file_glob": "**/fileCrypto.ts",
  "suppress_checklist": "C03",
  "reason": "deriveChunkIV uses HKDF with fileId+chunkIndex"
}
```

If a finding matches the pattern, is in the matching file, and references the specified checklist item → it's suppressed.

This whitelist grows over time. Every time you manually review a false positive, you can add a whitelist entry to prevent it from appearing again.

---

## 11. Step 7 — Checklists and Whitelists

### Checklist structure (YAML)

Each checklist is a YAML file with binary yes/no questions:

```yaml
checklist_id: crypto_aes_gcm     # Unique identifier
stage: crypto                     # Which stage loads this checklist
items:
  - id: C01                       # Item ID (referenced in findings)
    question: "Is every IV..."    # The security question
    severity: critical            # critical / high / medium
```

The `stage` field determines which checklist files get loaded for each audit stage. The orchestrator loads all YAMLs where the filename starts with the stage name.

### Coverage

| Stage | Files | Items | What it checks |
|-------|-------|-------|---------------|
| crypto | 3 YAMLs | 29 items | AES-GCM, Argon2id, ML-KEM-768 |
| signatures | 1 YAML | 8 items | Ed25519, ML-DSA-65 |
| key_lifecycle | 1 YAML | 12 items | Master Key lifecycle |
| filename_enc | 1 YAML | 7 items | Filename encryption |
| auth | 3 YAMLs | 17 items | JWT, OPAQUE, TOTP |
| recovery | 3 YAMLs | 18 items | Recovery codes, Shamir, Public Send |
| dataflow | 1 YAML | 8 items | Presigned URLs, R2, Redis |
| p2p | 1 YAML | 5 items | WebRTC |
| validation | 1 YAML | 8 items | Input validation |
| **Total** | **15 YAMLs** | **98 items** | |

---

## 12. Step 8 — Connecting Everything

### The run.sh script

A simple bash script that wraps Docker commands:

```bash
bash run.sh full
# Internally runs:
#   docker compose build
#   docker compose run --rm ast-parser         (all stages)
#   docker compose run --rm triage init        (index design docs)
#   docker compose run --rm triage triage      (filter findings)
```

### Network flow

```
Your PC (host)
├── Ollama (localhost:11434) ← running on GPU
│     ↑
│     │ HTTP API calls
│     ↓
├── Docker
│   ├── ast-parser container
│   │   ├── Reads /codebase (your CloudVault code, read-only)
│   │   ├── Reads /checklists (YAML files)
│   │   ├── Calls Ollama via host.docker.internal:11434
│   │   └── Writes to /reports (JSON findings)
│   │
│   └── triage container
│       ├── Reads /reports (findings from ast-parser)
│       ├── Reads /design-docs (CLAUDE.md etc.)
│       ├── Calls Ollama for embeddings via host.docker.internal:11434
│       ├── Uses /triage-db (ChromaDB vector store)
│       └── Writes to /reports (triaged findings)
│
└── reports/ folder ← you read the results here
```

---

## 13. How the Data Flows

A concrete example of one finding going through the entire pipeline:

**File**: `apps/web/src/lib/fileCrypto.ts`, line 142

### Stage 1: Tree-sitter
```
parser.py chunks the file → Chunk 3 (lines 130-200)
Functions in chunk: encryptFileChunk, deriveChunkIV
```

### Stage 2: Data flow tracing
```
data_flow.py traces:
  encrypt @ line 155:
    iv: DERIVED via deriveChunkIV [line 145]
    key: PARAMETER [line 130]
```

### Stage 3: Prompt building
```
prompt_builder.py creates a prompt with:
  - The code (lines 130-200 with line numbers)
  - The crypto traces
  - The AES-GCM checklist (C01-C10)
```

### Stage 4: DeepSeek runs 3 times
```
Run 1 (temp=0.1): [{"checklist_item": "C09", "finding": "chunks can be reordered..."}]
Run 2 (temp=0.3): [{"checklist_item": "C09", "finding": "chunk index not in AAD..."}]
Run 3 (temp=0.5): []
```

### Stage 5: Cross-validation
```
C09 found by 2/3 runs → consensus = 0.67
```

### Stage 6: Triage Layer 1 (auto-filter)
```
✓ Has checklist_item (C09)
✓ Lines exist in file
✓ Evidence found in source
✓ Not a duplicate
✓ Consensus >= 0.5
→ Passed Layer 1
```

### Stage 7: Triage Layer 2 (embedding similarity)
```
Finding: "chunks can be reordered without detection"
Closest design doc section: "Chunked encryption (5MB chunks) with deriveChunkIV..."
Distance: 0.52 (above 0.35 threshold)
→ NOT a known design decision → Passed Layer 2 → Status: "validated"
```

### Stage 8: Triage Layer 3 (whitelist)
```
No whitelist entry matches → Passes
Final status: "validated", confidence: 0.52
```

### Output in triaged report
```json
{
  "file": "apps/web/src/lib/fileCrypto.ts",
  "line_start": 142,
  "line_end": 158,
  "severity": "high",
  "checklist_item": "C09",
  "finding": "Chunks can be reordered without detection — chunk index is not bound to AAD",
  "consensus": 0.67,
  "triage_status": "validated"
}
```

---

## 14. Key Decisions and Why

### Why Docker and not just Python scripts?

**Isolation**. The audit pipeline has different dependencies from CloudVault. Without Docker, installing tree-sitter and chromadb could conflict with your Node.js tooling. Docker keeps everything separate.

### Why Ollama on host instead of in Docker?

**Simplicity + GPU access**. Getting NVIDIA GPU passthrough in Docker on Windows requires extra setup (NVIDIA Container Toolkit). Since Ollama already works with your GPU, we just connect to it from the containers.

### Why 3 runs per chunk?

**Cross-validation reduces false positives**. A 7B model hallucinating the same issue 3 times with different temperatures is unlikely. Consensus scoring (1.0 = 3/3, 0.67 = 2/3) gives confidence levels.

### Why tree-sitter instead of just sending raw code?

**Context window**. DeepSeek R1 7B has ~8K token context. A file like `useMasterKey.ts` is 1000+ lines — too big. Tree-sitter lets us split at function boundaries and pre-compute data flow traces, reducing what the model needs to reason about.

### Why nomic-embed-text for triage?

**Already installed**. You already had it in Ollama. It produces good-quality 768-dim embeddings for semantic similarity. No need for a separate Python embedding model like sentence-transformers.

### Why YAML for checklists?

**Easy to edit**. Adding a new security question is as simple as adding 3 lines to a YAML file. No code changes needed — just rebuild the Docker image.

### Why JSON for reports?

**Machine-readable**. The RAG system (D:\Projects\RAG) can index JSON directly. Other AI tools can parse it. And you can still read it in VS Code with pretty formatting.
