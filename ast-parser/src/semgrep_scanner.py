"""
Semgrep integration for deterministic static analysis.
Runs Semgrep rules and provides findings that can be injected as hints into LLM prompts.
"""

import json
import subprocess
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class SemgrepFinding:
    rule_id: str
    file: str
    line_start: int
    line_end: int
    severity: str
    message: str
    matched_code: str = ""
    metadata: dict = field(default_factory=dict)


def run_semgrep(
    codebase_root: Path,
    rules_dir: Path,
    target_files: list[Path] | None = None,
) -> list[SemgrepFinding]:
    """
    Run Semgrep with our custom rules and return structured findings.

    Args:
        codebase_root: Path to the codebase to scan
        rules_dir: Path to directory containing .yaml rule files
        target_files: Optional list of specific files to scan
    """
    cmd = [
        "semgrep",
        "--config", str(rules_dir),
        "--json",
        "--no-git-ignore",
        "--timeout", "60",
    ]

    if target_files:
        for f in target_files:
            cmd.append(str(f))
    else:
        cmd.append(str(codebase_root))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        # Semgrep not installed
        return []
    except subprocess.TimeoutExpired:
        return []

    # Parse JSON output
    findings = []
    try:
        output = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return []

    for r in output.get("results", []):
        rel_path = r.get("path", "")
        # Make path relative to codebase root if absolute
        try:
            rel_path = str(Path(rel_path).relative_to(codebase_root))
        except ValueError:
            pass
        rel_path = rel_path.replace("\\", "/")

        findings.append(SemgrepFinding(
            rule_id=r.get("check_id", "unknown"),
            file=rel_path,
            line_start=r.get("start", {}).get("line", 0),
            line_end=r.get("end", {}).get("line", 0),
            severity=r.get("extra", {}).get("severity", "WARNING"),
            message=r.get("extra", {}).get("message", ""),
            matched_code=r.get("extra", {}).get("lines", "").strip(),
            metadata=r.get("extra", {}).get("metadata", {}),
        ))

    return findings


def get_semgrep_hints_for_chunk(
    all_findings: list[SemgrepFinding],
    file_path: str,
    line_start: int,
    line_end: int,
) -> list[SemgrepFinding]:
    """Filter Semgrep findings that overlap with a code chunk."""
    # Normalize paths for comparison
    norm_path = file_path.replace("\\", "/")
    hints = []
    for f in all_findings:
        f_path = f.file.replace("\\", "/")
        if f_path != norm_path and not norm_path.endswith(f_path) and not f_path.endswith(norm_path):
            continue
        # Check line overlap
        if f.line_start <= line_end and f.line_end >= line_start:
            hints.append(f)
    return hints


def format_semgrep_for_prompt(findings: list[SemgrepFinding]) -> str:
    """Format Semgrep findings as hints to inject into the LLM prompt."""
    if not findings:
        return ""

    lines = ["STATIC ANALYSIS HINTS (deterministic — these are confirmed patterns):"]
    for i, f in enumerate(findings, 1):
        sev = f.severity.upper()
        cwe = f.metadata.get("cwe", "")
        checklist_map = f.metadata.get("checklist_map", "")

        line = f"  {i}. [{sev}] {f.rule_id} @ line {f.line_start}"
        if cwe:
            line += f" ({cwe})"
        if checklist_map:
            line += f" [maps to {checklist_map}]"
        line += f": {f.message}"
        lines.append(line)

        if f.matched_code:
            # Truncate long code
            code = f.matched_code[:150]
            lines.append(f"     Code: {code}")

    return "\n".join(lines) + "\n"


def save_semgrep_report(findings: list[SemgrepFinding], report_path: Path) -> None:
    """Save Semgrep findings as a JSON report for cross-validation by triage."""
    report = {
        "tool": "semgrep",
        "total_findings": len(findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "file": f.file,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "severity": f.severity,
                "message": f.message,
                "matched_code": f.matched_code,
                "metadata": f.metadata,
            }
            for f in findings
        ],
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
