#!/bin/bash
# CloudVault Crypto Audit Pipeline — Runner Script
# Usage:
#   ./run.sh audit [stage...]     Run audit (all stages or specific ones)
#   ./run.sh audit crypto         Run only the crypto stage
#   ./run.sh triage-init          Initialize design doc embeddings
#   ./run.sh triage [report.json] Run triage on latest or specified report
#   ./run.sh full                 Run audit + triage end-to-end
#   ./run.sh build                Build Docker images only
#   ./run.sh depgraph             Build and print dependency graph
#   ./run.sh semgrep              Run Semgrep standalone (no LLM)
#   ./run.sh audit-quick [stage]  Quick audit (no depgraph, no adversarial)

set -e

COMMAND=${1:-help}
shift 2>/dev/null || true

case "$COMMAND" in
  build)
    echo "Building Docker images..."
    docker compose build
    echo "Done."
    ;;

  audit)
    echo "Running crypto audit..."
    docker compose run --rm ast-parser "$@"
    ;;

  audit-quick)
    echo "Running quick audit (no depgraph, no adversarial)..."
    ENABLE_DEPGRAPH=false ENABLE_ADVERSARIAL=false \
      docker compose run --rm ast-parser "$@"
    ;;

  triage-init)
    echo "Initializing design doc embeddings..."
    docker compose run --rm triage init
    ;;

  triage)
    echo "Running triage pipeline..."
    docker compose run --rm triage triage "$@"
    ;;

  depgraph)
    echo "Building dependency graph..."
    ENABLE_SEMGREP=false ENABLE_ADVERSARIAL=false RUNS_PER_CHUNK=0 \
      docker compose run --rm ast-parser "$@"
    ;;

  semgrep)
    echo "Running Semgrep standalone..."
    docker compose run --rm ast-parser bash -c \
      "semgrep --config /app/semgrep-rules /codebase --json > /reports/semgrep_standalone_\$(date +%Y%m%d_%H%M%S).json && echo 'Semgrep report saved to /reports/'"
    ;;

  dashboard)
    echo "Starting Audit Dashboard on http://localhost:7800 ..."
    cd dashboard && pip install -q -r requirements.txt 2>/dev/null && python app.py
    ;;

  full)
    echo "=== FULL AUDIT PIPELINE ==="
    echo ""
    echo "Step 1/3: Building images..."
    docker compose build
    echo ""
    echo "Step 2/3: Running audit (all stages)..."
    docker compose run --rm ast-parser "$@"
    echo ""
    echo "Step 3/3: Running triage..."
    # Init embeddings if triage-db is empty
    if [ ! -f "./triage-db/chroma.sqlite3" ]; then
      echo "  Initializing design doc embeddings (first run)..."
      docker compose run --rm triage init
    fi
    docker compose run --rm triage triage
    echo ""
    echo "=== PIPELINE COMPLETE ==="
    echo "Reports in ./reports/"
    ls -la ./reports/*.json 2>/dev/null | tail -5
    ;;

  help|*)
    echo "CloudVault Crypto Audit Pipeline"
    echo ""
    echo "Usage: ./run.sh <command> [args]"
    echo ""
    echo "Commands:"
    echo "  build                Build Docker images"
    echo "  audit [stage...]     Run audit (all stages or specific: crypto, auth, etc.)"
    echo "  audit-quick [stage]  Quick audit (no depgraph, no adversarial pass)"
    echo "  triage-init          Initialize design doc embeddings in ChromaDB"
    echo "  triage [report.json] Run triage on latest (or specified) report"
    echo "  full                 Run complete pipeline: audit → triage"
    echo "  depgraph             Build and display dependency graph only"
    echo "  semgrep              Run Semgrep standalone (deterministic SAST, no LLM)"
    echo "  dashboard            Open web dashboard (http://localhost:7800)"
    echo ""
    echo "Feature flags (env vars):"
    echo "  ENABLE_DEPGRAPH=true|false   Cross-file dependency graph (default: true)"
    echo "  ENABLE_SEMGREP=true|false    Semgrep static analysis (default: true)"
    echo "  ENABLE_ADVERSARIAL=true|false Adversarial red-team pass (default: true)"
    echo "  ENABLE_FEW_SHOT=true|false   Few-shot examples in prompt (default: true)"
    echo "  MODELS=model1,model2         Multi-model orchestration"
    echo ""
    echo "Available stages:"
    echo "  crypto, signatures, key_lifecycle, filename_enc,"
    echo "  auth, recovery, dataflow, p2p, validation"
    echo ""
    echo "Examples:"
    echo "  ./run.sh full                              # Full audit, all features"
    echo "  ./run.sh audit crypto                      # Only audit crypto stage"
    echo "  ./run.sh audit crypto auth                 # Audit crypto + auth stages"
    echo "  ./run.sh audit-quick crypto                # Quick audit (no depgraph/adversarial)"
    echo "  ./run.sh semgrep                           # Semgrep only (fast, deterministic)"
    echo "  ENABLE_DEPGRAPH=false ./run.sh audit crypto  # Audit without dependency graph"
    echo "  MODELS=deepseek-r1:7b,qwen2.5-coder:7b ./run.sh audit crypto  # Multi-model"
    echo "  ./run.sh triage                            # Triage latest report"
    echo "  ./run.sh dashboard                         # Open web dashboard"
    ;;
esac
