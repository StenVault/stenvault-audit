"""v2 audit entrypoint: whole-file (Path 1), agentic (Path 2), diff (Path 3), compare.

Usage:
  entrypoint_v2.py audit-v2 [stage ...]
  entrypoint_v2.py agentic  [stage ...]
  entrypoint_v2.py diff     [base_ref]      # default: HEAD~1
  entrypoint_v2.py compare  <old.json> <new.json>
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

from rich.console import Console

import entrypoint as legacy  # reuse STAGES + resolve_files + load_checklists
from src.llm_client import OllamaClient, config_from_env
from src.few_shot_examples import get_few_shot_examples
from src import audit_v2, agentic_audit, diff_audit, compare as compare_mod

console = Console()

CODEBASE = Path(os.environ.get("CODEBASE_PATH", "/codebase"))
REPORTS = Path(os.environ.get("REPORTS_PATH", "/reports"))
ENABLE_FEW_SHOT = os.environ.get("ENABLE_FEW_SHOT", "true").lower() == "true"


def _clients() -> tuple[OllamaClient, OllamaClient]:
    auditor = OllamaClient(config_from_env("AUDIT"))
    verifier = OllamaClient(config_from_env("VERIFIER"))
    return auditor, verifier


def _stage_for_file(rel_path: str) -> str:
    """Map a changed file to a stage via the legacy glob table; validation last."""
    rp = rel_path.replace("\\", "/")
    for stage, patterns in legacy.STAGES.items():
        for pat in patterns:
            if Path(rp).match(pat) or rp.endswith(pat.replace("*", "")):
                return stage
    return "validation"


def _write(name: str, mode: str, findings: list[dict], extra: dict) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = REPORTS / f"{name}_{ts}.json"
    path.write_text(json.dumps({
        "mode": mode,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        **extra,
        "findings": findings,
    }, indent=2), encoding="utf-8")
    return path


def _run(mode: str, stages: list[str]):
    auditor, verifier = _clients()
    few_shot = get_few_shot_examples() if ENABLE_FEW_SHOT else ""
    console.print(f"[bold]v2 audit[/bold] mode={mode} "
                  f"auditor={auditor.cfg.model} verifier={verifier.cfg.model}")

    stages = stages or list(legacy.STAGES.keys())
    all_findings: list[dict] = []
    stats: dict = {}
    for stage in stages:
        files = legacy.resolve_files(legacy.STAGES.get(stage, []))
        checklists = legacy.load_checklists(stage)
        console.print(f"\n[cyan]stage {stage}[/cyan] — {len(files)} files")
        for fp in files:
            rel = str(fp.relative_to(CODEBASE))
            console.print(f"  [bold]{rel}[/bold]")
            all_findings.extend(_audit_one(mode, auditor, verifier, fp, rel, checklists, stage, few_shot, stats=stats))

    path = _write(mode, mode, all_findings,
                  {"stages_run": stages, "auditor": auditor.cfg.model, "verifier_stats": stats})
    console.print(f"\n[green]{len(all_findings)} confirmed findings "
                  f"({stats.get('raw',0)} raw, {stats.get('suppressed',0)} suppressed by verifier) "
                  f"→ {path.name}[/green]")


def _audit_one(mode, auditor, verifier, fp, rel, checklists, stage, few_shot, enrichment="", stats=None):
    if mode == "agentic":
        return agentic_audit.audit_file(
            auditor, verifier, str(fp), rel, checklists, stage,
            codebase_root=str(CODEBASE), stats=stats, log=console.print,
        )
    return audit_v2.audit_file(
        auditor, verifier, str(fp), rel, checklists, stage,
        few_shot=few_shot, enrichment=enrichment, stats=stats, log=console.print,
    )


def _run_diff(base: str):
    auditor, verifier = _clients()
    few_shot = get_few_shot_examples() if ENABLE_FEW_SHOT else ""
    use_agent = os.environ.get("DIFF_AGENTIC", "false").lower() == "true"
    mode = "agentic" if use_agent else "whole_file"
    console.print(f"[bold]diff audit[/bold] base={base} mode={mode}")

    try:
        changed = diff_audit.changed_files(str(CODEBASE), base)
    except RuntimeError as e:
        console.print(f"[red]git error: {e}[/red]")
        sys.exit(1)
    console.print(f"  {len(changed)} changed .ts files")

    all_findings: list[dict] = []
    stats: dict = {}
    for item in changed:
        rel = item["rel_path"]
        stage = _stage_for_file(rel)
        checklists = legacy.load_checklists(stage)
        console.print(f"  [bold]{rel}[/bold] (stage={stage}, {len(item['ranges'])} hunks)")
        all_findings.extend(_audit_one(
            mode, auditor, verifier, CODEBASE / rel, rel, checklists, stage, few_shot,
            enrichment=diff_audit.focus_note(item["ranges"]), stats=stats,
        ))

    path = _write("diff", f"diff:{mode}", all_findings,
                  {"base": base, "changed_files": [c["rel_path"] for c in changed],
                   "verifier_stats": stats})
    console.print(f"\n[green]{len(all_findings)} confirmed findings "
                  f"({stats.get('raw',0)} raw, {stats.get('suppressed',0)} suppressed) → {path.name}[/green]")


def _run_compare(old: str, new: str):
    md = compare_mod.compare(REPORTS / old if not Path(old).is_absolute() else Path(old),
                             REPORTS / new if not Path(new).is_absolute() else Path(new))
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = REPORTS / f"compare_{ts}.md"
    out.write_text(md, encoding="utf-8")
    console.print(md)
    console.print(f"\n[green]→ {out.name}[/green]")


def main():
    if len(sys.argv) < 2:
        console.print(__doc__)
        sys.exit(1)
    cmd, rest = sys.argv[1], sys.argv[2:]
    REPORTS.mkdir(exist_ok=True)

    if cmd == "audit-v2":
        _run("whole_file", rest)
    elif cmd == "agentic":
        _run("agentic", rest)
    elif cmd == "diff":
        _run_diff(rest[0] if rest else "HEAD~1")
    elif cmd == "compare":
        if len(rest) < 2:
            console.print("[red]compare needs <old.json> <new.json>[/red]")
            sys.exit(1)
        _run_compare(rest[0], rest[1])
    else:
        console.print(f"[red]unknown command: {cmd}[/red]")
        console.print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
