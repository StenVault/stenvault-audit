"""
CloudVault Audit Triage Pipeline.
Processes raw findings from the AST parser through 6 layers of filtering.

Layers:
  1:   Auto-filter (rule-based)
  1.5: AST evidence verification
  2:   Embedding similarity (design docs)
  2.5: Semgrep cross-validation
  3:   Known-good whitelist
  4:   Semantic deduplication
  5:   Composite confidence scoring
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table

from src.auto_filter import auto_filter
from src.embedding_triage import embedding_triage, init_design_doc_db
from src.whitelist import whitelist_triage
from src.ast_evidence import verify_evidence_ast
from src.semgrep_crossval import semgrep_cross_validate
from src.semantic_dedup import semantic_dedup
from src.confidence_scorer import apply_confidence_scores

console = Console()

REPORTS = Path(os.environ.get("REPORTS_PATH", "/reports"))
CODEBASE = os.environ.get("CODEBASE_ROOT", "/codebase")


def find_latest_report(stage: str = "combined") -> Path | None:
    """Find the most recent report file for a stage."""
    pattern = f"{stage}_*.json"
    reports = sorted(REPORTS.glob(pattern), reverse=True)
    return reports[0] if reports else None


def find_latest_semgrep_report() -> Path | None:
    """Find the most recent Semgrep report."""
    reports = sorted(REPORTS.glob("semgrep_*.json"), reverse=True)
    return reports[0] if reports else None


def run_triage(report_path: Path) -> dict:
    """Run the full triage pipeline on a report."""
    console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
    console.print(f"  [bold]TRIAGE PIPELINE (6 layers)[/bold]")
    console.print(f"  Report: {report_path.name}")
    console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")

    with open(report_path) as f:
        report = json.load(f)

    findings = report.get("findings", [])
    total = len(findings)
    console.print(f"  Total findings to triage: [bold]{total}[/bold]\n")

    if not findings:
        console.print("  [green]No findings to triage.[/green]")
        return report

    # Layer 1: Auto-filter
    console.print("  [bold]Layer 1: Auto-filter (rule-based)[/bold]")
    findings = auto_filter(findings, CODEBASE)
    rejected_l1 = len([f for f in findings if f.get("triage_status") == "rejected"])
    passed_l1 = len([f for f in findings if f.get("triage_status") == "passed_layer1"])
    console.print(f"    Rejected: {rejected_l1} | Passed: {passed_l1}")

    # Layer 1.5: AST evidence verification
    console.print("\n  [bold]Layer 1.5: AST evidence verification[/bold]")
    findings = verify_evidence_ast(findings, CODEBASE)
    exact = len([f for f in findings if f.get("evidence_quality") == "exact"])
    fuzzy = len([f for f in findings if f.get("evidence_quality") == "fuzzy"])
    no_match = len([f for f in findings if f.get("evidence_quality") == "no_match"])
    console.print(f"    Evidence: exact={exact} | fuzzy={fuzzy} | no_match={no_match}")

    # Layer 2: Embedding similarity
    console.print("\n  [bold]Layer 2: Embedding similarity (design docs)[/bold]")
    findings = embedding_triage(findings)
    rejected_ml = len([f for f in findings if f.get("triage_status") == "rejected_by_ml"])
    validated = len([f for f in findings if f.get("triage_status") == "validated"])
    console.print(f"    Rejected by ML: {rejected_ml} | Validated: {validated}")

    # Layer 2.5: Semgrep cross-validation
    console.print("\n  [bold]Layer 2.5: Semgrep cross-validation[/bold]")
    semgrep_report = find_latest_semgrep_report()
    findings = semgrep_cross_validate(findings, semgrep_report)
    corroborated = len([f for f in findings if f.get("semgrep_corroborated") is True])
    not_corroborated = len([f for f in findings if f.get("semgrep_corroborated") is False])
    console.print(f"    Corroborated by Semgrep: {corroborated} | Not: {not_corroborated}")
    if semgrep_report:
        console.print(f"    [dim]Using: {semgrep_report.name}[/dim]")
    else:
        console.print(f"    [dim]No Semgrep report found — skipping cross-validation[/dim]")

    # Layer 3: Whitelist
    console.print("\n  [bold]Layer 3: Known-good whitelist[/bold]")
    findings = whitelist_triage(findings)
    whitelisted = len([f for f in findings if f.get("triage_status") == "whitelisted"])
    console.print(f"    Whitelisted: {whitelisted}")

    # Layer 4: Semantic deduplication
    console.print("\n  [bold]Layer 4: Semantic deduplication[/bold]")
    count_before = len(findings)
    findings = semantic_dedup(findings)
    count_after = len(findings)
    deduped = count_before - count_after
    console.print(f"    Merged: {deduped} duplicates removed ({count_before} → {count_after})")

    # Layer 5: Confidence scoring
    console.print("\n  [bold]Layer 5: Confidence scoring[/bold]")
    findings = apply_confidence_scores(findings)
    high_conf = len([f for f in findings if f.get("confidence_tier") == "high"])
    med_conf = len([f for f in findings if f.get("confidence_tier") == "medium"])
    low_conf = len([f for f in findings if f.get("confidence_tier") == "low"])
    console.print(f"    High confidence: {high_conf} | Medium: {med_conf} | Low: {low_conf}")

    # Final stats
    final_validated = len([f for f in findings if f.get("triage_status") == "validated"])

    # Save triaged report
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    triaged_path = REPORTS / f"triaged_{timestamp}.json"
    triaged_report = {
        "source_report": report_path.name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_input": total,
        "triage_summary": {
            "rejected_layer1": rejected_l1,
            "evidence_exact": exact,
            "evidence_fuzzy": fuzzy,
            "evidence_no_match": no_match,
            "rejected_by_ml": rejected_ml,
            "semgrep_corroborated": corroborated,
            "whitelisted": whitelisted,
            "deduped": deduped,
            "validated": final_validated,
            "confidence_high": high_conf,
            "confidence_medium": med_conf,
            "confidence_low": low_conf,
        },
        "findings": findings,
    }

    with open(triaged_path, "w") as f:
        json.dump(triaged_report, f, indent=2)

    # Print summary table
    console.print(f"\n")
    table = Table(title="Triage Results")
    table.add_column("Status", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Percentage", justify="right")

    statuses = {
        "rejected": ("Rejected (rules)", "red"),
        "rejected_by_ml": ("Rejected (ML)", "red"),
        "whitelisted": ("Whitelisted", "yellow"),
        "validated": ("Validated", "green bold"),
    }

    for status, (label, style) in statuses.items():
        count = len([f for f in findings if f.get("triage_status") == status])
        pct = f"{count/total*100:.1f}%" if total > 0 else "0%"
        table.add_row(f"[{style}]{label}[/]", str(count), pct)

    console.print(table)

    # Confidence breakdown for validated findings
    if final_validated > 0:
        conf_table = Table(title="Confidence Breakdown (Validated)")
        conf_table.add_column("Tier", style="cyan")
        conf_table.add_column("Count", justify="right")
        conf_table.add_row("[green]High (≥0.7)[/green]", str(high_conf))
        conf_table.add_row("[yellow]Medium (≥0.4)[/yellow]", str(med_conf))
        conf_table.add_row("[red]Low (<0.4)[/red]", str(low_conf))
        console.print(conf_table)

    console.print(f"\n  Triaged report: [bold]{triaged_path.name}[/bold]")
    console.print(f"  Actionable findings: [bold green]{final_validated}[/bold green]")

    # Print validated findings detail
    if final_validated > 0:
        console.print(f"\n[bold]Validated Findings:[/bold]")
        for f in sorted(
            [f for f in findings if f.get("triage_status") == "validated"],
            key=lambda x: (
                -x.get("confidence_score", 0),
                {"critical": 0, "high": 1, "medium": 2}.get(x.get("severity", ""), 3),
            ),
        ):
            sev = f.get("severity", "?")
            sev_color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(sev, "white")
            finding_type = f.get("finding_type", "checklist")
            type_tag = " [magenta][ADV][/magenta]" if finding_type == "adversarial" else ""
            conf = f.get("confidence_score", 0)
            semgrep_tag = " [green][SAST✓][/green]" if f.get("semgrep_corroborated") else ""
            console.print(
                f"  [{sev_color}][{sev.upper()}][/] "
                f"{f.get('file', '?')}:{f.get('line_start', '?')}-{f.get('line_end', '?')} "
                f"({f.get('checklist_item', '?')}) "
                f"conf={conf:.2f}{type_tag}{semgrep_tag}"
            )
            console.print(f"    {f.get('finding', '?')}")

    return triaged_report


def main():
    console.print("[bold]CloudVault Audit Triage Pipeline[/bold]\n")

    # Handle commands
    command = sys.argv[1] if len(sys.argv) > 1 else "triage"

    if command == "init":
        # Initialize design doc embeddings
        console.print("  [bold]Initializing design document embeddings...[/bold]")
        init_design_doc_db()
        console.print("  [green]Done.[/green]")
        return

    if command == "triage":
        # Find report to triage
        report_file = sys.argv[2] if len(sys.argv) > 2 else None

        if report_file:
            report_path = REPORTS / report_file
        else:
            report_path = find_latest_report("combined")
            if not report_path:
                # Try any stage report
                reports = sorted(REPORTS.glob("*.json"), reverse=True)
                reports = [r for r in reports if not r.name.startswith(("triaged_", "semgrep_"))]
                report_path = reports[0] if reports else None

        if not report_path or not report_path.exists():
            console.print("  [red]No report found. Run the audit first.[/red]")
            sys.exit(1)

        run_triage(report_path)
        return

    console.print(f"  [red]Unknown command: {command}[/red]")
    console.print(f"  Usage: entrypoint.py [init|triage] [report_file]")
    sys.exit(1)


if __name__ == "__main__":
    main()
