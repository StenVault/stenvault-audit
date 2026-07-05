"""Path 1 — whole-file static auditor.

Sends the entire file to a strong model with structured output, then runs one
adversarial self-verification pass to drop false positives (replacing chunking
and 3x-temperature consensus). Output is triage-compatible.
"""

from pathlib import Path

from src.prompt_builder import _format_checklists
from src.llm_client import OllamaClient, LLMError
from src.findings_schema import (
    AUDIT_FINDINGS_SCHEMA,
    VERIFIER_SCHEMA,
    normalize_finding,
)

# Above this, segment at function boundaries instead of sending the file whole.
MAX_WHOLE_LINES = 900


def _segments(file_path: str) -> list[tuple[str, int]]:
    """[(content, start_line)] — whole file when it fits, else large
    function-boundary chunks."""
    text = Path(file_path).read_text(encoding="utf-8", errors="replace")
    n_lines = text.count("\n") + 1
    if n_lines <= MAX_WHOLE_LINES:
        return [(text, 1)]

    from src.parser import chunk_file
    chunks = chunk_file(file_path, max_lines=MAX_WHOLE_LINES // 2)
    return [(c.content, c.line_start) for c in chunks] or [(text, 1)]


def _numbered(content: str, start_line: int) -> str:
    return "\n".join(
        f"{start_line + i:>4} | {line}" for i, line in enumerate(content.split("\n"))
    )


def _build_prompt(
    rel_path: str,
    numbered_code: str,
    checklists: list[dict],
    few_shot: str,
    enrichment: str,
) -> str:
    checklist_section = _format_checklists(checklists)
    extra = f"\n{enrichment}\n" if enrichment.strip() else ""
    fs = f"\n{few_shot}\n" if few_shot.strip() else ""
    return f"""You are a cryptographic security auditor reviewing StenVault, a zero-knowledge \
encrypted cloud storage system. The server NEVER sees file content, filenames, or passwords.

You are given a COMPLETE source file (all lines, including module-level code). Reason across
the whole file — data can flow between functions, and module-level constants (salts, configs)
matter. Do not assume anything outside what is shown; if a value's safety genuinely cannot be
determined from this file, do not flag it.

FILE: {rel_path}
{extra}{fs}
--- FILE START ---
{numbered_code}
--- FILE END ---

{checklist_section}

For each checklist item, decide COMPLIANT or VIOLATION. Report ONLY violations, each anchored
to exact line numbers with a verbatim evidence snippet copied from the code above. Do not invent
issues, and do not flag intentional zero-knowledge design patterns (deterministic HKDF-derived
IVs, extractable keys that are wrapped before storage, hardcoded HKDF domain-separator strings).
Return an empty findings array if there are no real violations."""


def _verify(
    verifier: OllamaClient,
    rel_path: str,
    numbered_code: str,
    findings: list[dict],
) -> list[dict]:
    """Refute each finding against the full file; drop false positives."""
    if not findings:
        return findings

    listed = "\n".join(
        f"[{i}] ({f.get('severity')}) lines {f.get('line_start')}-{f.get('line_end')}: "
        f"{f.get('finding')} | evidence: {f.get('evidence')[:160]}"
        for i, f in enumerate(findings)
    )
    prompt = f"""You are a skeptical senior reviewer double-checking an auditor's findings on a
zero-knowledge encrypted storage file. For EACH finding, decide if it is a real, exploitable
violation ("confirmed"), a "false_positive" (intended design, misread line, or unsupported by
the code), or "uncertain". Default to "false_positive" when the evidence does not clearly
support the claim. Be strict — most crypto false positives come from flagging safe deterministic
IV derivation, wrapped-but-extractable keys, and HKDF domain separators.

FILE: {rel_path}
--- FILE ---
{numbered_code}
--- END ---

FINDINGS TO JUDGE:
{listed}

Return a verdict for every index above."""

    try:
        result = verifier.generate_structured(prompt, VERIFIER_SCHEMA)
    except LLMError:
        return findings  # fail open: keep findings if the verifier errors

    verdicts = {
        _int(v.get("index")): (v.get("verdict"), v.get("reason", ""))
        for v in result.get("verdicts", [])
    }
    kept = []
    for i, f in enumerate(findings):
        verdict, reason = verdicts.get(i, ("uncertain", "no verdict returned"))
        if verdict == "false_positive":
            continue
        f["verifier_verdict"] = verdict
        f["verifier_reason"] = reason
        # Map the verdict onto the triage consensus signal.
        f["consensus"] = 1.0 if verdict == "confirmed" else 0.5
        f["consensus_type"] = "self-verified"
        kept.append(f)
    return kept


def audit_file(
    auditor: OllamaClient,
    verifier: OllamaClient,
    file_path: str,
    rel_path: str,
    checklists: list[dict],
    stage: str,
    *,
    few_shot: str = "",
    enrichment: str = "",
    stats: dict | None = None,
    log=lambda *_: None,
) -> list[dict]:
    """Audit one file whole; return verified, triage-ready findings."""
    findings: list[dict] = []
    for content, start_line in _segments(file_path):
        numbered = _numbered(content, start_line)
        prompt = _build_prompt(rel_path, numbered, checklists, few_shot, enrichment)
        try:
            raw = auditor.generate_structured(prompt, AUDIT_FINDINGS_SCHEMA)
        except LLMError as e:
            log(f"    [red]auditor error: {e}[/red]")
            continue
        seg_raw = [
            normalize_finding(
                f, rel_path, stage,
                source="whole_file", model=auditor.cfg.model,
            )
            for f in raw.get("findings", [])
        ]
        log(f"    {len(seg_raw)} raw findings (lines {start_line}-{start_line + content.count(chr(10))})")

        # Verify against the same segment view the auditor saw.
        kept = _verify(verifier, rel_path, numbered, seg_raw)
        _tally(stats, seg_raw, kept)
        findings.extend(kept)
    return findings


def _tally(stats: dict | None, raw: list[dict], kept: list[dict]):
    """Record raw/confirmed/suppressed counts so nothing is dropped silently."""
    if stats is None:
        return
    stats["files"] = stats.get("files", 0) + 1
    stats["raw"] = stats.get("raw", 0) + len(raw)
    stats["confirmed"] = stats.get("confirmed", 0) + sum(
        1 for f in kept if f.get("verifier_verdict") == "confirmed")
    stats["suppressed"] = stats.get("suppressed", 0) + (len(raw) - len(kept))


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return -1
