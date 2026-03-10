# How to Use the CloudVault Crypto Audit Pipeline

## Quick Start

Open a terminal (Git Bash, PowerShell, or CMD) and navigate to the project:

```bash
cd D:\Projects\local-audit
```

### Prerequisites (must be running before you start)

1. **Docker Desktop** must be running (check the whale icon in your system tray)
2. **Ollama** must be running (check: open http://localhost:11434 in your browser — should say "Ollama is running")

If Ollama is not running, open a terminal and type:
```bash
ollama serve
```

---

## Commands

### Run a full audit (all 9 stages)

```bash
bash run.sh full
```

This will:
1. Build the Docker images (first time takes ~2 min, after that ~5 seconds)
2. Run the audit across all 9 cryptographic domains
3. Initialize the design doc embeddings (first time only)
4. Run the triage pipeline to filter false positives
5. Output the final report to `./reports/`

**Estimated time**: 30-90 minutes for the full audit (depends on GPU speed).

### Run a single stage

If you only want to audit one domain (much faster, 5-15 min):

```bash
bash run.sh audit crypto          # AES-GCM, key derivation, hybrid PQC
bash run.sh audit signatures      # Ed25519 + ML-DSA-65
bash run.sh audit key_lifecycle   # Master Key generation → destruction
bash run.sh audit filename_enc    # Filename encryption
bash run.sh audit auth            # JWT, OPAQUE, MFA/TOTP
bash run.sh audit recovery        # Recovery codes, Shamir, Public Send
bash run.sh audit dataflow        # Presigned URLs, R2, Redis
bash run.sh audit p2p             # WebRTC signaling
bash run.sh audit validation      # Input validation, SQL injection, XSS
```

You can also combine stages:
```bash
bash run.sh audit crypto auth     # Run crypto + auth together
```

### Run triage on results

After an audit finishes, run triage to filter false positives:

```bash
# First time only: index the design docs for ML comparison
bash run.sh triage-init

# Run triage on the latest report
bash run.sh triage
```

### Rebuild after changes

If you edit any Python code, checklists, or whitelists:
```bash
bash run.sh build
```

---

## Where to See What's Happening

### While the audit is running

**Option 1 — Docker Desktop GUI:**
1. Open Docker Desktop
2. Click "Containers" in the left sidebar
3. You will see `audit-ast-parser` running
4. Click on it → click "Logs" tab → you see the live output

**Option 2 — Terminal:**
```bash
# See running containers
docker ps

# See live logs of the audit
docker logs -f audit-ast-parser

# See live logs of triage
docker logs -f audit-triage
```

**Option 3 — Task Manager:**
- Open Task Manager (Ctrl+Shift+Esc)
- Look for `ollama_llama_server` — this is the DeepSeek model running
- It will use a lot of GPU (check the "GPU" tab)
- Also look for `com.docker.backend` — this is the Docker container

### When the audit finishes

Reports appear in the `reports/` folder:

```bash
ls reports/
```

You will see files like:
```
crypto_20260227_104500.json        ← Raw findings from crypto stage
auth_20260227_110000.json          ← Raw findings from auth stage
combined_20260227_112000.json      ← All findings merged
triaged_20260227_113000.json       ← After false-positive filtering (THIS IS WHAT YOU WANT)
```

### Reading a report

Open any JSON report in VS Code or run:
```bash
# See a quick summary (PowerShell)
cat reports/triaged_*.json | python -m json.tool | head -50

# Or open in VS Code
code reports/
```

The important fields in each finding:
```json
{
  "file": "apps/web/src/lib/fileCrypto.ts",   // Which file
  "line_start": 142,                            // Where it starts
  "line_end": 158,                              // Where it ends
  "severity": "high",                           // critical / high / medium
  "checklist_item": "C03",                      // Which check failed
  "finding": "IV reuse risk...",                 // What the problem is
  "evidence": "const iv = ...",                  // The actual code
  "suggestion": "Include fileId...",             // How to fix it
  "consensus": 1.0,                             // 3/3 runs agreed (1.0 = confident)
  "triage_status": "validated"                   // Passed all filters (real issue)
}
```

**Priority order for reading findings:**
1. `triage_status: "validated"` + `severity: "critical"` — fix immediately
2. `triage_status: "validated"` + `severity: "high"` — fix soon
3. `triage_status: "validated"` + `severity: "medium"` — review when possible
4. Ignore everything with `triage_status: "rejected"` or `"whitelisted"`

---

## Common Situations

### "Ollama is not responding"

```bash
# Check if Ollama is running
curl http://localhost:11434

# If not, start it
ollama serve

# Verify the model is available
ollama list
```

### "Docker build fails"

```bash
# Clean and rebuild from scratch
docker compose build --no-cache
```

### "I want to add a new checklist item"

1. Open the relevant YAML file in `checklists/`
2. Add a new item following the same format:
   ```yaml
   - id: C11
     question: "Your security question here?"
     severity: critical
   ```
3. Rebuild: `bash run.sh build`
4. Run the stage: `bash run.sh audit crypto`

### "The audit found a false positive I want to suppress"

1. Open the relevant JSON file in `whitelist/`
2. Add a new entry:
   ```json
   {
     "pattern": "the code pattern to match",
     "file_glob": "**/filename.ts",
     "suppress_checklist": "C03",
     "reason": "Why this is intentional"
   }
   ```
3. Re-run triage: `bash run.sh triage`

### "I want to audit a single file"

Currently the pipeline audits all files in a stage. To focus on one file, temporarily edit the STAGES dict in `ast-parser/entrypoint.py` to only include that file, then rebuild and run.

### "I updated my CloudVault code, how do I re-audit?"

Just run the audit again — it always reads from your live codebase:
```bash
bash run.sh audit crypto    # or whichever stage changed
bash run.sh triage          # filter results
```

The codebase is mounted read-only, so the audit can never modify your code.

---

## Folder Structure

```
D:\Projects\local-audit/
├── run.sh                  ← The main command you use
├── docker-compose.yml      ← Docker configuration
│
├── reports/                ← OUTPUT: all audit reports go here
│   ├── crypto_*.json       ← Raw findings per stage
│   ├── combined_*.json     ← All stages merged
│   └── triaged_*.json      ← After false-positive filtering ← READ THIS
│
├── checklists/             ← Security checklists (15 YAML files, 98 items)
├── whitelist/              ← Known-good patterns to suppress false positives
├── design-docs/            ← Your CLAUDE.md, NEW_DAY.md, SOVEREIGN_ROADMAP.md
│
├── ast-parser/             ← Audit engine code (you don't need to touch this)
└── triage/                 ← Triage pipeline code (you don't need to touch this)
```
