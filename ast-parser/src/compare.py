"""Side-by-side comparison of two finding reports (e.g. legacy vs v2)."""

import json
from pathlib import Path


def _key(f: dict) -> tuple:
    """Loose identity: same file, checklist item, and ~10-line neighborhood."""
    return (
        (f.get("file") or "").replace("\\", "/"),
        f.get("checklist_item") or "?",
        int(f.get("line_start") or 0) // 10,
    )


def _load(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("findings", data if isinstance(data, list) else [])


def _sev_counts(findings: list[dict]) -> dict:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        out[f.get("severity", "low")] = out.get(f.get("severity", "low"), 0) + 1
    return out


def compare(old_path: Path, new_path: Path) -> str:
    old, new = _load(old_path), _load(new_path)
    old_keys = {_key(f) for f in old}
    new_keys = {_key(f) for f in new}
    shared = old_keys & new_keys

    old_only = [f for f in old if _key(f) not in shared]
    new_only = [f for f in new if _key(f) not in shared]

    def rows(findings):
        return "\n".join(
            f"| {f.get('severity','?')} | `{f.get('file','?')}`:{f.get('line_start','?')} "
            f"| {f.get('checklist_item','?')} | {(f.get('finding','') or '')[:80]} |"
            for f in sorted(findings, key=lambda x: x.get("severity", "z"))
        ) or "| — | — | — | _none_ |"

    md = f"""# Audit comparison

| | Legacy (`{old_path.name}`) | v2 (`{new_path.name}`) |
|---|---:|---:|
| Total findings | {len(old)} | {len(new)} |
| Critical | {_sev_counts(old)['critical']} | {_sev_counts(new)['critical']} |
| High | {_sev_counts(old)['high']} | {_sev_counts(new)['high']} |
| Medium | {_sev_counts(old)['medium']} | {_sev_counts(new)['medium']} |
| Overlap (same file/item/±10 lines) | {len(shared)} | {len(shared)} |

## Only in legacy ({len(old_only)})
| Sev | Location | Item | Finding |
|---|---|---|---|
{rows(old_only)}

## Only in v2 ({len(new_only)})
| Sev | Location | Item | Finding |
|---|---|---|---|
{rows(new_only)}
"""
    return md
