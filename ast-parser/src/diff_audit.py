"""Path 3 — git-diff scoping.

Collects the TypeScript files (and changed line ranges) touched since a base ref
so the auditor runs only on what changed. The read-only bind mount means git
runs with safe.directory disabled.
"""

import re
import subprocess
from pathlib import Path


def _git(root: str, *args: str) -> str:
    out = subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", root, *args],
        capture_output=True, text=True, timeout=60,
    )
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or f"git {' '.join(args)} failed")
    return out.stdout


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_files(root: str, base: str) -> list[dict]:
    """[{rel_path, ranges}] for added/modified .ts/.tsx files since `base`.

    `ranges` are (start, end) line spans on the new side, for focusing the prompt.
    """
    names = _git(root, "diff", "--name-only", "--diff-filter=d", f"{base}...HEAD")
    files = []
    for rel in names.splitlines():
        rel = rel.strip()
        if not rel.endswith((".ts", ".tsx")) or not (Path(root) / rel).is_file():
            continue
        files.append({"rel_path": rel, "ranges": _ranges(root, base, rel)})
    return files


def _ranges(root: str, base: str, rel: str) -> list[tuple[int, int]]:
    diff = _git(root, "diff", "-U0", f"{base}...HEAD", "--", rel)
    ranges = []
    for line in diff.splitlines():
        m = _HUNK.match(line)
        if m:
            start = int(m.group(1))
            count = int(m.group(2) or 1)
            if count:
                ranges.append((start, start + count - 1))
    return ranges


def focus_note(ranges: list[tuple[int, int]]) -> str:
    """Enrichment line telling the auditor which lines actually changed."""
    if not ranges:
        return ""
    spans = ", ".join(f"{a}-{b}" if a != b else str(a) for a, b in ranges)
    return f"CHANGED LINES (prioritize, but read the whole file for context): {spans}"
