"""Schemas for constrained LLM output + normalization to the triage shape."""

SEVERITIES = ["critical", "high", "medium", "low"]

AUDIT_FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "checklist_item": {"type": "string"},
                    "severity": {"type": "string", "enum": SEVERITIES},
                    "line_start": {"type": "integer"},
                    "line_end": {"type": "integer"},
                    "finding": {"type": "string"},
                    "evidence": {"type": "string"},
                    "suggestion": {"type": "string"},
                },
                "required": ["checklist_item", "severity", "line_start", "finding", "evidence"],
            },
        }
    },
    "required": ["findings"],
}

VERIFIER_SCHEMA = {
    "type": "object",
    "properties": {
        "verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "index": {"type": "integer"},
                    "verdict": {
                        "type": "string",
                        "enum": ["confirmed", "false_positive", "uncertain"],
                    },
                    "reason": {"type": "string"},
                },
                "required": ["index", "verdict", "reason"],
            },
        }
    },
    "required": ["verdicts"],
}

# One agentic step is either a tool call or, when tool=="done", the findings.
AGENT_STEP_SCHEMA = {
    "type": "object",
    "properties": {
        "thought": {"type": "string"},
        "tool": {
            "type": "string",
            "enum": ["read_file", "grep", "get_symbol", "done"],
        },
        "args": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "pattern": {"type": "string"},
                "symbol": {"type": "string"},
            },
        },
        "findings": AUDIT_FINDINGS_SCHEMA["properties"]["findings"],
    },
    "required": ["thought", "tool"],
}


def normalize_finding(
    raw: dict,
    file: str,
    stage: str,
    *,
    source: str,
    model: str,
    consensus: float | None = None,
    finding_type: str = "checklist",
) -> dict:
    """Coerce a schema-validated finding into the triage-compatible shape."""
    line_start = _as_int(raw.get("line_start"), 0)
    line_end = _as_int(raw.get("line_end"), line_start)
    if line_end < line_start:
        line_end = line_start
    f = {
        "file": file,
        "stage": stage,
        "checklist_item": (raw.get("checklist_item") or "").strip() or None,
        "severity": raw.get("severity", "medium"),
        "line_start": line_start,
        "line_end": line_end,
        "finding": raw.get("finding", "").strip(),
        "evidence": raw.get("evidence", "").strip(),
        "suggestion": raw.get("suggestion", "").strip(),
        "finding_type": finding_type,
        "audit_source": source,   # "whole_file" | "agentic"
        "audit_model": model,
    }
    if consensus is not None:
        f["consensus"] = consensus
    return f


def _as_int(v, default: int) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default
