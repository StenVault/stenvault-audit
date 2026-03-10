"""
Layer 2.5: Cross-validation of LLM findings against Semgrep deterministic results.
Boosts confidence for corroborated findings and penalizes uncorroborated ones.
"""

import json
from pathlib import Path


def semgrep_cross_validate(
    findings: list[dict],
    semgrep_report_path: Path | None,
) -> list[dict]:
    """
    Cross-validate LLM findings against Semgrep report.

    - If Semgrep also flagged same file+line → confidence_boost += 0.2
    - If Semgrep did not flag that area → confidence_penalty += 0.1
    - Adds: semgrep_corroborated (bool), semgrep_rule_match (str|None)
    """
    # Load Semgrep findings
    semgrep_findings = []
    if semgrep_report_path and semgrep_report_path.exists():
        try:
            with open(semgrep_report_path) as f:
                report = json.load(f)
            semgrep_findings = report.get("findings", [])
        except (json.JSONDecodeError, OSError):
            pass

    # Build Semgrep index: (normalized_file, line) -> finding info
    semgrep_index: dict[str, list[dict]] = {}
    for sf in semgrep_findings:
        file_key = sf.get("file", "").replace("\\", "/")
        for line in range(sf.get("line_start", 0), sf.get("line_end", 0) + 1):
            key = f"{file_key}:{line}"
            semgrep_index.setdefault(key, []).append(sf)

    for f in findings:
        # Skip already-rejected findings
        status = f.get("triage_status", "")
        if status == "rejected":
            continue

        if not semgrep_findings:
            # No Semgrep data available — skip cross-validation
            f["semgrep_corroborated"] = None
            f["semgrep_rule_match"] = None
            continue

        file_path = f.get("file", "").replace("\\", "/")
        line_start = f.get("line_start", 0)
        line_end = f.get("line_end", 0)

        # Check if Semgrep flagged any line in this finding's range (±3 lines fuzzy)
        corroborated = False
        matched_rule = None

        for line in range(max(1, line_start - 3), line_end + 4):
            key = f"{file_path}:{line}"
            if key in semgrep_index:
                corroborated = True
                matched_rule = semgrep_index[key][0].get("rule_id", "unknown")
                break

        f["semgrep_corroborated"] = corroborated
        f["semgrep_rule_match"] = matched_rule

        if corroborated:
            f["confidence_boost"] = f.get("confidence_boost", 0) + 0.2
        else:
            f["confidence_penalty"] = f.get("confidence_penalty", 0) + 0.1

    return findings
