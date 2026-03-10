"""
CloudVault Crypto Audit Pipeline — AST Parser + LLM Orchestrator.
Parses code with tree-sitter, traces crypto data flow, prompts LLM(s),
and collects structured findings.

Features (controlled by env vars):
  ENABLE_DEPGRAPH    — Cross-file dependency graph (Phase 1)
  ENABLE_SEMGREP     — Semgrep deterministic SAST (Phase 2)
  MODELS             — Multi-model orchestration (Phase 3)
  ENABLE_ADVERSARIAL — Adversarial red-team pass (Phase 4)
"""

import os
import sys
import json
import yaml
import requests
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from src.parser import chunk_file, parse_file, get_relevant_imports, find_crypto_calls
from src.data_flow import trace_crypto_data_flow
from src.prompt_builder import build_audit_prompt, build_adversarial_prompt

console = Console()

# Configuration from environment
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://host.docker.internal:11434")
MODEL = os.environ.get("MODEL", "deepseek-r1:7b")
CODEBASE = Path(os.environ.get("CODEBASE_PATH", "/codebase"))
REPORTS = Path(os.environ.get("REPORTS_PATH", "/reports"))
CHECKLISTS = Path(os.environ.get("CHECKLISTS_PATH", "/checklists"))
RUNS_PER_CHUNK = int(os.environ.get("RUNS_PER_CHUNK", "3"))
MAX_CHUNK_LINES = int(os.environ.get("MAX_CHUNK_LINES", "200"))
TEMPERATURES = [0.1, 0.3, 0.5]

# Feature flags
ENABLE_DEPGRAPH = os.environ.get("ENABLE_DEPGRAPH", "true").lower() == "true"
ENABLE_SEMGREP = os.environ.get("ENABLE_SEMGREP", "true").lower() == "true"
ENABLE_ADVERSARIAL = os.environ.get("ENABLE_ADVERSARIAL", "true").lower() == "true"
ENABLE_FEW_SHOT = os.environ.get("ENABLE_FEW_SHOT", "true").lower() == "true"
DESIGN_DOCS_DIR = os.environ.get("DESIGN_DOCS_DIR", "/design-docs")

# Stage → target file globs (relative to codebase root)
STAGES = {
    "crypto": [
        "apps/web/src/lib/fileCrypto.ts",
        "apps/web/src/lib/fileEncryptor.ts",
        "apps/web/src/lib/streamingDecrypt.ts",
        "apps/web/src/lib/hybridFileCrypto.ts",
        "apps/web/src/lib/signedFileCrypto.ts",
        "apps/web/src/hooks/masterKeyCrypto.ts",
        "apps/web/src/lib/publicSendCrypto.ts",
        "apps/web/src/lib/shareCrypto.ts",
        "apps/web/src/lib/chatFileCrypto.ts",
        "apps/web/src/hooks/useMasterKey.ts",
        "packages/shared/src/platform/crypto/utils.ts",
    ],
    "signatures": [
        "apps/web/src/lib/platform/webHybridSignatureProvider.ts",
        "apps/api/src/_core/hybridSignature*.ts",
        "packages/shared/src/platform/hybridSignature*.ts",
    ],
    "key_lifecycle": [
        "apps/web/src/hooks/useMasterKey.ts",
        "apps/web/src/hooks/masterKeyCrypto.ts",
        "apps/api/src/_core/encryption*.ts",
        "apps/api/src/_core/deviceApproval*.ts",
    ],
    "filename_enc": [
        "apps/web/src/hooks/useFilenameDecryption.ts",
        "apps/web/src/hooks/useFilename*.ts",
        "apps/web/src/lib/fileCrypto.ts",
    ],
    "auth": [
        "apps/api/src/_core/opaqueAuth.ts",
        "apps/web/src/lib/opaqueClient.ts",
        "apps/api/src/_core/auth/*.ts",
        "apps/api/src/middleware/auth*.ts",
        "apps/api/src/_core/mfa*.ts",
    ],
    "recovery": [
        "apps/web/src/lib/recoveryCodeUtils.ts",
        "apps/web/src/lib/publicSendCrypto.ts",
        "apps/web/src/hooks/usePublicSend.ts",
        "apps/api/src/_core/publicSend/*.ts",
        "apps/api/src/_core/shamirRecovery*.ts",
    ],
    "dataflow": [
        "apps/api/src/_core/files/*.ts",
        "apps/api/src/_core/publicSend/*.ts",
        "apps/api/src/lib/s3.ts",
        "apps/api/src/lib/redis.ts",
    ],
    "p2p": [
        "apps/api/src/_core/p2p/*.ts",
    ],
    "validation": [
        "apps/api/src/_core/**/*.ts",
    ],
}


# --- Phase 3: Multi-Model Support ---

@dataclass
class ModelConfig:
    name: str
    num_ctx: int = 8192
    num_predict: int = 2048
    temperature: float = 0.2


def parse_model_configs() -> list[ModelConfig]:
    """
    Parse model configurations from environment variables.
    MODELS=qwen2.5-coder:32b,deepseek-r1:32b  (comma-separated)
    MODEL_CONFIGS={"qwen2.5-coder:32b":{"num_ctx":16384,"num_predict":4096}}
    Falls back to MODEL env var for backwards compatibility.
    """
    models_str = os.environ.get("MODELS", "")
    if not models_str:
        # Backwards compatible: single model from MODEL env var
        return [ModelConfig(name=MODEL)]

    model_names = [m.strip() for m in models_str.split(",") if m.strip()]
    if not model_names:
        return [ModelConfig(name=MODEL)]

    # Parse optional per-model configs
    configs_str = os.environ.get("MODEL_CONFIGS", "{}")
    try:
        configs = json.loads(configs_str)
    except json.JSONDecodeError:
        configs = {}

    result = []
    for name in model_names:
        mc = ModelConfig(name=name)
        if name in configs:
            c = configs[name]
            mc.num_ctx = c.get("num_ctx", mc.num_ctx)
            mc.num_predict = c.get("num_predict", mc.num_predict)
            mc.temperature = c.get("temperature", mc.temperature)
        result.append(mc)

    return result


# --- Core Pipeline Functions ---

def resolve_files(patterns: list[str]) -> list[Path]:
    """Resolve glob patterns to actual file paths, deduplicating."""
    files: set[Path] = set()
    for pattern in patterns:
        resolved = list(CODEBASE.glob(pattern))
        if not resolved:
            console.print(f"  [dim]No files matched: {pattern}[/dim]")
        files.update(resolved)
    return sorted(files)


def load_checklists(stage: str) -> list[dict]:
    """Load all YAML checklists matching a stage name."""
    checklists = []
    for yaml_file in sorted(CHECKLISTS.glob(f"{stage}_*.yaml")):
        with open(yaml_file) as f:
            data = yaml.safe_load(f)
            if data:
                checklists.append(data)
    if not checklists:
        console.print(f"  [yellow]Warning: No checklists found for stage '{stage}'[/yellow]")
    return checklists


def query_ollama(prompt: str, model_config: ModelConfig, temperature: float | None = None) -> str:
    """Send prompt to LLM via Ollama and return response text."""
    temp = temperature if temperature is not None else model_config.temperature

    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": model_config.name,
                "prompt": prompt,
                "temperature": temp,
                "stream": False,
                "options": {
                    "num_ctx": model_config.num_ctx,
                    "num_predict": model_config.num_predict,
                },
            },
            timeout=600,
        )
        response.raise_for_status()
        return response.json().get("response", "")
    except requests.exceptions.ConnectionError:
        console.print(f"  [red]ERROR: Cannot connect to Ollama at {OLLAMA_URL}[/red]")
        console.print(f"  [red]Make sure Ollama is running on your host machine.[/red]")
        sys.exit(1)
    except requests.exceptions.Timeout:
        console.print(f"  [yellow]Warning: Ollama request timed out (600s)[/yellow]")
        return ""
    except Exception as e:
        console.print(f"  [yellow]Warning: Ollama error: {e}[/yellow]")
        return ""


def parse_findings(raw_response: str, chunk_file: str, chunk_start: int, chunk_end: int, stage: str) -> list[dict]:
    """Parse LLM's JSON response into structured findings."""
    if not raw_response.strip():
        return []

    # DeepSeek R1 often wraps response in <think>...</think> tags — strip them
    response = raw_response
    think_end = response.rfind("</think>")
    if think_end >= 0:
        response = response[think_end + len("</think>"):].strip()

    try:
        # Find JSON array in response
        json_start = response.find("[")
        json_end = response.rfind("]") + 1
        if json_start >= 0 and json_end > json_start:
            text = response[json_start:json_end]
            findings = json.loads(text)
            if isinstance(findings, list):
                for f in findings:
                    f["file"] = chunk_file
                    f["chunk_line_start"] = chunk_start
                    f["chunk_line_end"] = chunk_end
                    f["stage"] = stage
                return findings
    except json.JSONDecodeError:
        pass

    # If response is just [] or empty-ish
    stripped = response.strip()
    if stripped in ("[]", "", "null", "No violations found.", "No violations found"):
        return []

    # Fallback: unparseable response
    return [{
        "file": chunk_file,
        "line_start": chunk_start,
        "line_end": chunk_end,
        "stage": stage,
        "severity": "unknown",
        "finding": stripped[:500],
        "checklist_item": None,
        "parse_error": True,
    }]


def parse_adversarial_findings(
    raw_response: str, chunk_file: str, chunk_start: int, chunk_end: int, stage: str
) -> list[dict]:
    """Parse adversarial prompt response into structured findings."""
    if not raw_response.strip():
        return []

    response = raw_response
    think_end = response.rfind("</think>")
    if think_end >= 0:
        response = response[think_end + len("</think>"):].strip()

    try:
        json_start = response.find("[")
        json_end = response.rfind("]") + 1
        if json_start >= 0 and json_end > json_start:
            text = response[json_start:json_end]
            items = json.loads(text)
            if isinstance(items, list):
                findings = []
                for item in items:
                    finding = {
                        "file": chunk_file,
                        "chunk_line_start": chunk_start,
                        "chunk_line_end": chunk_end,
                        "stage": stage,
                        "finding_type": "adversarial",
                        "severity": _map_exploitability_to_severity(item.get("exploitability", "medium")),
                        "finding": item.get("attack_vector", ""),
                        "evidence": item.get("evidence", ""),
                        "suggestion": f"Preconditions: {item.get('preconditions', 'N/A')}. Impact: {item.get('impact', 'N/A')}",
                        "attack_vector": item.get("attack_vector", ""),
                        "preconditions": item.get("preconditions", ""),
                        "impact": item.get("impact", ""),
                        "exploitability": item.get("exploitability", "medium"),
                    }
                    # Map affected lines
                    affected = item.get("affected_lines", [])
                    if affected:
                        finding["line_start"] = min(affected)
                        finding["line_end"] = max(affected)
                    else:
                        finding["line_start"] = chunk_start
                        finding["line_end"] = chunk_end
                    findings.append(finding)
                return findings
    except json.JSONDecodeError:
        pass

    return []


def _map_exploitability_to_severity(exploitability: str) -> str:
    """Map adversarial exploitability to severity."""
    return {"high": "critical", "medium": "high", "low": "medium"}.get(exploitability, "medium")


def merge_cross_validation(runs: list[list[dict]], model_names: list[str] | None = None) -> list[dict]:
    """Merge findings across multiple runs and compute consensus score."""
    if not runs:
        return []

    # Flatten all findings, tag with run index
    all_findings = []
    for run_idx, run_findings in enumerate(runs):
        for f in run_findings:
            f["_run"] = run_idx
            all_findings.append(f)

    if not all_findings:
        return []

    # Determine consensus type
    is_multi_model = model_names and len(set(model_names)) > 1

    # Group by (checklist_item, approximate line)
    groups: dict[str, list[dict]] = {}
    for f in all_findings:
        line = f.get('line_start') or 0
        key = f"{f.get('checklist_item', 'none')}:{line // 10}"
        groups.setdefault(key, []).append(f)

    merged = []
    for _key, group in groups.items():
        runs_present = len(set(f["_run"] for f in group))
        total_runs = len(runs)
        consensus = round(runs_present / total_runs, 2)

        # Take the finding from the first run as representative
        best = group[0].copy()
        best.pop("_run", None)
        best["consensus"] = consensus
        best["runs_agreed"] = runs_present
        best["total_runs"] = total_runs

        # Phase 3: Multi-model metadata
        if is_multi_model:
            best["consensus_type"] = "cross-model"
            best["models_agreed"] = [
                model_names[f["_run"]] for f in group
                if f["_run"] < len(model_names)
            ]
        else:
            best["consensus_type"] = "cross-temperature"

        merged.append(best)

    return merged


def run_stage(
    stage: str,
    selected_files: list[Path] | None = None,
    dep_graph=None,
    semgrep_findings=None,
    models: list[ModelConfig] | None = None,
) -> list[dict]:
    """Run a complete audit stage."""
    console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
    console.print(f"  [bold]STAGE: {stage.upper()}[/bold]")
    console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")

    files = selected_files or resolve_files(STAGES.get(stage, []))
    checklists = load_checklists(stage)
    all_findings = []

    if models is None:
        models = [ModelConfig(name=MODEL)]

    # Load few-shot examples if enabled
    few_shot_text = ""
    if ENABLE_FEW_SHOT:
        try:
            from src.few_shot_examples import get_few_shot_examples
            few_shot_text = get_few_shot_examples()
        except ImportError:
            pass

    # Import context enrichment if graph is available
    context_funcs = None
    if dep_graph is not None:
        try:
            from src import context_enrichment
            context_funcs = context_enrichment
        except ImportError:
            pass

    # Import semgrep scanner if findings are available
    semgrep_scanner = None
    if semgrep_findings:
        try:
            from src.semgrep_scanner import get_semgrep_hints_for_chunk, format_semgrep_for_prompt
            semgrep_scanner = (get_semgrep_hints_for_chunk, format_semgrep_for_prompt)
        except ImportError:
            pass

    if not files:
        console.print(f"  [yellow]No files to audit for stage '{stage}'[/yellow]")
        return []

    for file_path in files:
        rel_path = file_path.relative_to(CODEBASE)
        console.print(f"\n  [bold]Parsing:[/bold] {rel_path}")

        try:
            chunks = chunk_file(str(file_path), max_lines=MAX_CHUNK_LINES)
        except Exception as e:
            console.print(f"  [red]Parse error: {e}[/red]")
            continue

        root, source = parse_file(str(file_path))
        console.print(f"  [dim]  → {len(chunks)} chunks[/dim]")

        for i, chunk in enumerate(chunks):
            console.print(
                f"  [dim]  Chunk {i+1}/{len(chunks)} "
                f"(lines {chunk.line_start}-{chunk.line_end}, "
                f"fns: {', '.join(chunk.functions[:3])}{'...' if len(chunk.functions) > 3 else ''})"
                f"[/dim]"
            )

            # Get relevant imports for context
            imports = get_relevant_imports(root, source, chunk)

            # Trace crypto data flow (with optional graph)
            traces = trace_crypto_data_flow(
                chunk.content, chunk.line_start, str(rel_path), graph=dep_graph,
            )

            # --- Phase 2 & 4: Build enrichment context ---
            semgrep_hints = ""
            if semgrep_scanner and semgrep_findings:
                hints = semgrep_scanner[0](semgrep_findings, str(rel_path), chunk.line_start, chunk.line_end)
                semgrep_hints = semgrep_scanner[1](hints)

            cross_file_ctx = ""
            type_sigs = ""
            design_doc = ""
            if context_funcs and dep_graph:
                # Resolve parameter origins
                resolved = context_funcs.resolve_all_parameter_origins_for_chunk(
                    traces, str(rel_path), dep_graph,
                )
                cross_file_ctx = context_funcs.format_cross_file_context(resolved)

                # Get type signatures
                sigs = context_funcs.get_type_signatures_for_chunk(
                    chunk.content, dep_graph, str(rel_path), imports,
                )
                type_sigs = context_funcs.format_type_signatures(sigs)

                # Get design doc excerpt
                design_doc = context_funcs.get_relevant_design_doc(
                    chunk.content, traces, DESIGN_DOCS_DIR,
                )

            # Build prompt
            prompt = build_audit_prompt(
                chunk_content=chunk.content,
                chunk_start_line=chunk.line_start,
                chunk_end_line=chunk.line_end,
                functions=chunk.functions,
                imports=imports,
                crypto_traces=traces,
                checklists=checklists,
                file_path=str(rel_path),
                chunk_index=i + 1,
                total_chunks=len(chunks),
                semgrep_hints=semgrep_hints,
                cross_file_context=cross_file_ctx,
                type_signatures=type_sigs,
                design_doc_excerpt=design_doc,
                few_shot_examples=few_shot_text,
            )

            # --- Phase 3: Multi-model or multi-temperature ---
            runs_results = []
            model_names_used = []

            if len(models) == 1:
                # Backwards compatible: N temperatures with single model
                for run_idx in range(RUNS_PER_CHUNK):
                    temp = TEMPERATURES[run_idx] if run_idx < len(TEMPERATURES) else 0.3
                    console.print(f"    [dim]Run {run_idx+1}/{RUNS_PER_CHUNK} (model={models[0].name}, temp={temp})[/dim]", end="")

                    raw = query_ollama(prompt, models[0], temperature=temp)
                    findings = parse_findings(raw, str(rel_path), chunk.line_start, chunk.line_end, stage)

                    console.print(f" → [{'green' if not findings else 'yellow'}]{len(findings)} findings[/]")
                    runs_results.append(findings)
                    model_names_used.append(models[0].name)
            else:
                # Multi-model: each model once
                for m_idx, model_config in enumerate(models):
                    console.print(
                        f"    [dim]Run {m_idx+1}/{len(models)} (model={model_config.name})[/dim]",
                        end="",
                    )

                    raw = query_ollama(prompt, model_config)
                    findings = parse_findings(raw, str(rel_path), chunk.line_start, chunk.line_end, stage)

                    console.print(f" → [{'green' if not findings else 'yellow'}]{len(findings)} findings[/]")
                    runs_results.append(findings)
                    model_names_used.append(model_config.name)

            # Cross-validate
            merged = merge_cross_validation(runs_results, model_names_used)
            all_findings.extend(merged)

            # --- Phase 4: Adversarial pass ---
            if chunk.crypto_calls and ENABLE_ADVERSARIAL:
                console.print(f"    [dim]Adversarial pass...[/dim]", end="")

                adversarial_prompt = build_adversarial_prompt(
                    chunk_content=chunk.content,
                    chunk_start_line=chunk.line_start,
                    chunk_end_line=chunk.line_end,
                    functions=chunk.functions,
                    imports=imports,
                    crypto_traces=traces,
                    file_path=str(rel_path),
                    semgrep_hints=semgrep_hints,
                    cross_file_context=cross_file_ctx,
                )

                adversarial_raw = query_ollama(adversarial_prompt, models[0])
                adversarial_findings = parse_adversarial_findings(
                    adversarial_raw, str(rel_path), chunk.line_start, chunk.line_end, stage,
                )

                console.print(f" → [{'green' if not adversarial_findings else 'magenta'}]{len(adversarial_findings)} attack vectors[/]")
                all_findings.extend(adversarial_findings)

    # Write stage report
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = REPORTS / f"{stage}_{timestamp}.json"
    report = {
        "stage": stage,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": models[0].name if models else MODEL,
        "models_used": list(set(m.name for m in models)) if models else [MODEL],
        "features": {
            "depgraph": ENABLE_DEPGRAPH,
            "semgrep": ENABLE_SEMGREP,
            "adversarial": ENABLE_ADVERSARIAL,
            "few_shot": ENABLE_FEW_SHOT,
            "multi_model": len(models) > 1 if models else False,
        },
        "total_findings": len(all_findings),
        "findings": all_findings,
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    console.print(f"\n  [green]Stage '{stage}' complete: {len(all_findings)} findings → {report_path.name}[/green]")
    return all_findings


def print_summary(all_findings: list[dict]):
    """Print a summary table of findings."""
    table = Table(title="Audit Summary")
    table.add_column("Stage", style="cyan")
    table.add_column("Total", justify="right")
    table.add_column("Critical", justify="right", style="red")
    table.add_column("High", justify="right", style="yellow")
    table.add_column("Medium", justify="right", style="blue")
    table.add_column("Adversarial", justify="right", style="magenta")
    table.add_column("Consensus ≥0.67", justify="right", style="green")

    by_stage: dict[str, list[dict]] = {}
    for f in all_findings:
        by_stage.setdefault(f.get("stage", "?"), []).append(f)

    for stage, findings in sorted(by_stage.items()):
        total = len(findings)
        critical = len([f for f in findings if f.get("severity") == "critical"])
        high = len([f for f in findings if f.get("severity") == "high"])
        medium = len([f for f in findings if f.get("severity") == "medium"])
        adversarial = len([f for f in findings if f.get("finding_type") == "adversarial"])
        high_consensus = len([f for f in findings if f.get("consensus", 0) >= 0.67])
        table.add_row(stage, str(total), str(critical), str(high), str(medium), str(adversarial), str(high_consensus))

    console.print(table)


def main():
    REPORTS.mkdir(exist_ok=True)

    # Parse model configs (Phase 3)
    models = parse_model_configs()
    primary_model = models[0].name

    # Check Ollama connectivity
    console.print(f"[bold]CloudVault Crypto Audit Pipeline[/bold]")
    console.print(f"  Ollama: {OLLAMA_URL}")
    console.print(f"  Model(s): {', '.join(m.name for m in models)}")
    console.print(f"  Codebase: {CODEBASE}")
    console.print(f"  Runs per chunk: {RUNS_PER_CHUNK}")
    console.print(f"  Features: depgraph={ENABLE_DEPGRAPH}, semgrep={ENABLE_SEMGREP}, "
                   f"adversarial={ENABLE_ADVERSARIAL}, few_shot={ENABLE_FEW_SHOT}")
    console.print()

    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=10)
        available_models = [m["name"] for m in r.json().get("models", [])]
        for mc in models:
            if mc.name not in available_models and f"{mc.name}:latest" not in available_models:
                console.print(f"  [yellow]Warning: Model '{mc.name}' not found in Ollama. Available: {available_models}[/yellow]")
            else:
                console.print(f"  [green]Model '{mc.name}' available.[/green]")
    except Exception as e:
        console.print(f"  [red]Cannot connect to Ollama: {e}[/red]")
        sys.exit(1)

    # --- Phase 1: Build dependency graph ---
    dep_graph = None
    if ENABLE_DEPGRAPH:
        try:
            from src.dependency_graph import build_dependency_graph
            console.print(f"\n  [bold]Building cross-file dependency graph...[/bold]")
            dep_graph = build_dependency_graph(str(CODEBASE))
        except ImportError:
            console.print(f"  [yellow]Warning: dependency_graph module not available[/yellow]")
        except Exception as e:
            console.print(f"  [yellow]Warning: dependency graph failed: {e}[/yellow]")

    # --- Phase 2: Run Semgrep ---
    semgrep_findings = []
    if ENABLE_SEMGREP:
        try:
            from src.semgrep_scanner import run_semgrep, save_semgrep_report
            rules_dir = Path("/app/semgrep-rules")
            if rules_dir.exists():
                console.print(f"\n  [bold]Running Semgrep static analysis...[/bold]")
                semgrep_findings = run_semgrep(CODEBASE, rules_dir)
                console.print(f"  [dim]  → {len(semgrep_findings)} Semgrep findings[/dim]")

                # Save Semgrep report for triage cross-validation
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                semgrep_report_path = REPORTS / f"semgrep_{timestamp}.json"
                save_semgrep_report(semgrep_findings, semgrep_report_path)
                console.print(f"  [dim]  → Saved: {semgrep_report_path.name}[/dim]")
            else:
                console.print(f"  [yellow]Warning: semgrep-rules/ directory not found[/yellow]")
        except ImportError:
            console.print(f"  [yellow]Warning: semgrep_scanner module not available[/yellow]")
        except Exception as e:
            console.print(f"  [yellow]Warning: Semgrep failed: {e}[/yellow]")

    # Determine which stages to run
    stages_to_run = sys.argv[1:] if len(sys.argv) > 1 else list(STAGES.keys())

    # Validate stage names
    for s in stages_to_run:
        if s not in STAGES:
            console.print(f"  [red]Unknown stage: '{s}'. Available: {list(STAGES.keys())}[/red]")
            sys.exit(1)

    console.print(f"  Stages: {', '.join(stages_to_run)}")
    console.print()

    all_findings = []
    for stage in stages_to_run:
        findings = run_stage(
            stage,
            dep_graph=dep_graph,
            semgrep_findings=semgrep_findings,
            models=models,
        )
        all_findings.extend(findings)

    # Write combined report
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    combined_path = REPORTS / f"combined_{timestamp}.json"
    combined = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": primary_model,
        "models_used": list(set(m.name for m in models)),
        "stages_run": stages_to_run,
        "features": {
            "depgraph": ENABLE_DEPGRAPH,
            "semgrep": ENABLE_SEMGREP,
            "adversarial": ENABLE_ADVERSARIAL,
            "few_shot": ENABLE_FEW_SHOT,
            "multi_model": len(models) > 1,
        },
        "total_findings": len(all_findings),
        "by_severity": {
            sev: len([f for f in all_findings if f.get("severity") == sev])
            for sev in ("critical", "high", "medium", "low", "unknown")
        },
        "by_stage": {
            stage: len([f for f in all_findings if f.get("stage") == stage])
            for stage in stages_to_run
        },
        "by_type": {
            "checklist": len([f for f in all_findings if f.get("finding_type") != "adversarial"]),
            "adversarial": len([f for f in all_findings if f.get("finding_type") == "adversarial"]),
        },
        "findings": all_findings,
    }
    with open(combined_path, "w") as f:
        json.dump(combined, f, indent=2)

    console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
    console.print(f"  [bold]AUDIT COMPLETE[/bold]")
    console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")

    print_summary(all_findings)
    console.print(f"\n  Combined report: [bold]{combined_path.name}[/bold]")
    console.print(f"  Total findings:  [bold]{len(all_findings)}[/bold]")


if __name__ == "__main__":
    main()
