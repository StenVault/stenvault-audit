"""
Layer 3: Known-good pattern whitelist.
Suppresses findings that match documented intentional design patterns.
"""

import json
import os
import re
from pathlib import Path
from fnmatch import fnmatch

WHITELIST_DIR = Path(os.environ.get("WHITELIST_DIR", "/whitelist"))


def load_whitelist() -> list[dict]:
    """Load all whitelist JSON files."""
    whitelist = []
    for f in sorted(WHITELIST_DIR.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(data, list):
                whitelist.extend(data)
            elif isinstance(data, dict):
                whitelist.append(data)
        except (json.JSONDecodeError, OSError) as e:
            print(f"  Warning: Failed to load whitelist {f.name}: {e}")
    return whitelist


def whitelist_triage(findings: list[dict]) -> list[dict]:
    """Suppress findings that match whitelisted known-good patterns."""
    whitelist = load_whitelist()
    if not whitelist:
        return findings

    for f in findings:
        # Only check findings that are still pending validation
        if f.get("triage_status") not in ("validated", "passed_layer1"):
            continue

        evidence = f.get("evidence", "")
        finding_text = f.get("finding", "")
        file_path = f.get("file", "")
        checklist_item = f.get("checklist_item", "")

        for rule in whitelist:
            # Check pattern match (in evidence or finding text)
            pattern = rule.get("pattern", "")
            if not pattern:
                continue

            pattern_match = False
            try:
                if re.search(pattern, evidence, re.IGNORECASE):
                    pattern_match = True
                elif re.search(pattern, finding_text, re.IGNORECASE):
                    pattern_match = True
            except re.error:
                # Invalid regex, try literal match
                if pattern.lower() in evidence.lower() or pattern.lower() in finding_text.lower():
                    pattern_match = True

            if not pattern_match:
                continue

            # Check file glob (optional)
            file_glob = rule.get("file_glob")
            if file_glob and not fnmatch(file_path, file_glob):
                continue

            # Check checklist item (optional)
            suppress_checklist = rule.get("suppress_checklist")
            if suppress_checklist and suppress_checklist != checklist_item:
                continue

            # All checks passed — whitelist this finding
            f["triage_status"] = "whitelisted"
            f["triage_reason"] = rule.get("reason", "known-good pattern")
            break

    return findings
