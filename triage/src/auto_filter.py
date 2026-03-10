"""
Layer 1: Rule-based auto-filter.
Rejects findings that fail basic validation before ML processing.
"""

from pathlib import Path


def auto_filter(findings: list[dict], codebase_root: str) -> list[dict]:
    """
    Filter findings through rule-based checks:
    1. Must have a checklist_item (model didn't hallucinate)
    2. Lines must exist in the actual file
    3. Evidence must appear in the source
    4. No exact duplicates
    5. Consensus must be >= 0.5
    """
    seen: set[tuple] = set()

    for f in findings:
        # Skip already-rejected
        if f.get("triage_status") == "rejected":
            continue

        # Rule 1: Must reference a checklist item
        if not f.get("checklist_item"):
            f["triage_status"] = "rejected"
            f["triage_reason"] = "no_checklist_match"
            continue

        # Rule 2: Reject parse errors
        if f.get("parse_error"):
            f["triage_status"] = "rejected"
            f["triage_reason"] = "unparseable_response"
            continue

        # Rule 3: Line range must exist in the file
        file_path = Path(codebase_root) / f.get("file", "")
        if file_path.exists():
            try:
                with open(file_path, encoding="utf-8", errors="replace") as fh:
                    total_lines = sum(1 for _ in fh)
                line_start = f.get("line_start", 0)
                line_end = f.get("line_end", 0)
                if line_start > total_lines or line_end > total_lines:
                    f["triage_status"] = "rejected"
                    f["triage_reason"] = "line_out_of_bounds"
                    continue
            except OSError:
                pass

        # Rule 4: Evidence should appear in the source (relaxed — substring match)
        evidence = f.get("evidence", "")
        if evidence and file_path.exists():
            try:
                with open(file_path, encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
                ls = max(0, f.get("line_start", 1) - 1)
                le = min(len(lines), f.get("line_end", len(lines)))
                # Expand range by 5 lines each direction for fuzzy match
                ls = max(0, ls - 5)
                le = min(len(lines), le + 5)
                chunk_text = " ".join(lines[ls:le]).replace("\n", " ")
                evidence_normalized = " ".join(evidence.split())
                # Check if a significant substring matches (at least 20 chars)
                if len(evidence_normalized) > 20:
                    # Check if the core part of evidence exists
                    core = evidence_normalized[:60]
                    if core not in " ".join(chunk_text.split()):
                        f["triage_status"] = "rejected"
                        f["triage_reason"] = "evidence_not_in_source"
                        continue
            except OSError:
                pass

        # Rule 5: Deduplication
        dedup_key = (
            f.get("file", ""),
            f.get("checklist_item", ""),
            f.get("line_start", 0) // 10,  # Group lines within 10-line window
        )
        if dedup_key in seen:
            f["triage_status"] = "rejected"
            f["triage_reason"] = "duplicate"
            continue
        seen.add(dedup_key)

        # Rule 6: Low consensus
        if f.get("consensus", 1.0) < 0.5:
            f["triage_status"] = "rejected"
            f["triage_reason"] = "low_consensus"
            continue

        # Passed layer 1
        f["triage_status"] = "passed_layer1"

    return findings
