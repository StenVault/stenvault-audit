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

  adversarial)
    echo "=== ADVERSARIAL TESTING ==="
    echo "Starting full StenVault stack + attack suite..."
    echo ""
    docker compose -f adversarial/docker-compose.yml build
    echo ""
    echo "Starting pipeline in background..."
    docker compose -f adversarial/docker-compose.yml up -d 2>&1 | tee adversarial/reports/run-$(date +%Y%m%d_%H%M%S).log
    echo ""
    echo "Waiting for report-generator to complete (this takes 5-15 min)..."
    echo "  Follow live: docker compose -f adversarial/docker-compose.yml logs -f"
    echo ""
    docker compose -f adversarial/docker-compose.yml wait report-generator 2>&1
    EXIT_CODE=$?
    echo ""
    echo "=== Pipeline finished (exit $EXIT_CODE) ==="
    echo ""
    # Show key container logs
    echo "--- Seed ---"
    docker compose -f adversarial/docker-compose.yml logs seed 2>/dev/null | tail -15
    echo ""
    echo "--- Nuclei ---"
    docker compose -f adversarial/docker-compose.yml logs nuclei 2>/dev/null | tail -20
    echo ""
    echo "--- ZAP ---"
    docker compose -f adversarial/docker-compose.yml logs zap 2>/dev/null | tail -20
    echo ""
    echo "--- Report Generator ---"
    docker compose -f adversarial/docker-compose.yml logs report-generator 2>/dev/null
    echo ""
    # Show summary report
    if [ -f adversarial/reports/SUMMARY.md ]; then
      echo "=== SUMMARY ==="
      cat adversarial/reports/SUMMARY.md
    fi
    echo ""
    echo "Full report: adversarial/reports/SUMMARY.md"
    echo "Cleaning up..."
    docker compose -f adversarial/docker-compose.yml down
    exit $EXIT_CODE
    ;;

  adversarial-up)
    echo "Starting StenVault stack (stays running for manual testing)..."
    docker compose -f adversarial/docker-compose.yml up -d app db redis redis-rest minio minio-init
    echo ""
    echo "App: http://localhost:3000"
    echo "MinIO Console: http://localhost:9001 (minioadmin/minioadmin)"
    echo "PostgreSQL: localhost:5433"
    echo "Redis: localhost:6380"
    echo ""
    echo "Run attacks manually:"
    echo "  docker compose -f adversarial/docker-compose.yml run --rm nuclei"
    echo "  docker compose -f adversarial/docker-compose.yml run --rm race-tester"
    echo ""
    echo "Stop: docker compose -f adversarial/docker-compose.yml down"
    ;;

  adversarial-chaos)
    echo "=== CHAOS ENGINEERING ==="
    docker compose -f adversarial/docker-compose.yml build chaos-tester
    docker compose -f adversarial/docker-compose.yml up -d app db redis minio minio-init toxiproxy toxiproxy-init
    echo "Waiting for stack..."
    sleep 10
    docker compose -f adversarial/docker-compose.yml run --rm chaos-tester
    echo "Reports in adversarial/reports/"
    ;;

  adversarial-fuzz)
    DURATION=${1:-300}
    echo "=== LONG-RUNNING FUZZER (${DURATION}s) ==="
    FUZZ_DURATION=$DURATION docker compose -f adversarial/docker-compose.yml --profile fuzz run --rm fuzzer
    ;;

  adversarial-down)
    echo "Stopping adversarial stack..."
    docker compose -f adversarial/docker-compose.yml down -v
    echo "Done."
    ;;

  help|*)
    echo "StenVault Audit Pipeline"
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
    echo "Adversarial (live attack simulation):"
    echo "  adversarial          Full attack: build stack, seed, Nuclei + ZAP + race + chaos"
    echo "  adversarial-up       Start stack only (for manual testing / Burp)"
    echo "  adversarial-chaos    Run chaos engineering (Toxiproxy kills Redis/DB)"
    echo "  adversarial-fuzz [s] Run Nuclei in loop for N seconds (default 300)"
    echo "  adversarial-down     Stop and cleanup adversarial stack"
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
