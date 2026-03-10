"""
Layer 4: Semantic deduplication.
Groups findings by root cause (same file + function + similar description)
and merges duplicates, keeping the highest severity.
"""

import re
from collections import defaultdict


def semantic_dedup(findings: list[dict]) -> list[dict]:
    """
    Deduplicate findings that describe the same root cause.

    Groups by (file, function_name), then uses text similarity to detect
    findings about the same issue. Merged findings keep highest severity
    and combine evidence.
    """
    # Separate rejected findings (pass through unchanged)
    active = []
    rejected = []
    for f in findings:
        status = f.get("triage_status", "")
        if status == "rejected" or status == "rejected_by_ml":
            rejected.append(f)
        else:
            active.append(f)

    # Group active findings by (file, function/checklist_item)
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in active:
        file_path = f.get("file", "unknown")
        # Group by file + approximate function (using line range) + checklist category
        checklist = f.get("checklist_item", "none")
        category = _get_checklist_category(checklist)
        function_key = _get_function_key(f)
        key = f"{file_path}::{function_key}::{category}"
        groups[key].append(f)

    # Within each group, merge similar findings
    deduped = []
    for _key, group in groups.items():
        if len(group) == 1:
            deduped.append(group[0])
            continue

        # Sort by severity (critical > high > medium > low > unknown)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        group.sort(key=lambda f: severity_order.get(f.get("severity", "unknown"), 4))

        # Try to merge similar findings
        merged_set: list[dict] = []
        used = set()

        for i, f1 in enumerate(group):
            if i in used:
                continue

            cluster = [f1]
            used.add(i)

            for j, f2 in enumerate(group):
                if j in used:
                    continue

                if _are_similar(f1, f2):
                    cluster.append(f2)
                    used.add(j)

            # Merge cluster into one finding
            merged = _merge_findings(cluster)
            merged_set.append(merged)

        deduped.extend(merged_set)

    return rejected + deduped


def _get_checklist_category(checklist_item: str) -> str:
    """Extract category prefix from checklist item (e.g., 'C01' -> 'C', 'KD05' -> 'KD')."""
    if not checklist_item:
        return "none"
    match = re.match(r'^([A-Z]+)', checklist_item)
    return match.group(1) if match else "none"


def _get_function_key(finding: dict) -> str:
    """Get a key representing the function scope of a finding."""
    # Use line range to approximate function scope (within 50-line windows)
    line_start = finding.get("line_start", 0)
    return str(line_start // 50)


def _are_similar(f1: dict, f2: dict) -> bool:
    """Check if two findings describe the same root cause."""
    # Same checklist item is a strong signal
    if f1.get("checklist_item") == f2.get("checklist_item"):
        # Check line proximity (within 20 lines)
        l1 = f1.get("line_start", 0)
        l2 = f2.get("line_start", 0)
        if abs(l1 - l2) <= 20:
            return True

    # Check text similarity of finding descriptions
    desc1 = f1.get("finding", "")
    desc2 = f2.get("finding", "")
    if desc1 and desc2:
        sim = _jaccard_similarity(desc1, desc2)
        if sim > 0.5:
            return True

    return False


def _jaccard_similarity(text1: str, text2: str) -> float:
    """Compute Jaccard similarity between two texts (word-level)."""
    words1 = set(text1.lower().split())
    words2 = set(text2.lower().split())

    if not words1 or not words2:
        return 0.0

    intersection = words1 & words2
    union = words1 | words2

    return len(intersection) / len(union)


def _merge_findings(cluster: list[dict]) -> dict:
    """Merge a cluster of similar findings into one, keeping best info."""
    if len(cluster) == 1:
        return cluster[0]

    # Use the highest-severity finding as base
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    cluster.sort(key=lambda f: severity_order.get(f.get("severity", "unknown"), 4))
    best = cluster[0].copy()

    # Expand line range to cover all findings
    all_starts = [f.get("line_start", 0) for f in cluster if f.get("line_start")]
    all_ends = [f.get("line_end", 0) for f in cluster if f.get("line_end")]
    if all_starts:
        best["line_start"] = min(all_starts)
    if all_ends:
        best["line_end"] = max(all_ends)

    # Combine consensus scores (take max)
    best["consensus"] = max(f.get("consensus", 0) for f in cluster)
    best["runs_agreed"] = max(f.get("runs_agreed", 0) for f in cluster)

    # Track merge metadata
    best["merged_count"] = len(cluster)
    best["merged_checklist_items"] = list(set(
        f.get("checklist_item", "") for f in cluster if f.get("checklist_item")
    ))

    # Keep best evidence (longest)
    all_evidence = [f.get("evidence", "") for f in cluster if f.get("evidence")]
    if all_evidence:
        best["evidence"] = max(all_evidence, key=len)

    # Combine suggestions
    all_suggestions = list(set(f.get("suggestion", "") for f in cluster if f.get("suggestion")))
    if all_suggestions:
        best["suggestion"] = all_suggestions[0]

    return best
