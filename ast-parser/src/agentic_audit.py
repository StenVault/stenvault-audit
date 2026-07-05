"""Path 2 — agentic auditor.

The model drives its own investigation through read-only tools (read_file, grep,
get_symbol) over a bounded ReAct loop, then findings go through the same
adversarial verifier as Path 1. Tool calls are schema-constrained rather than
relying on native tool-calling, so any local model works.
"""

import os
import re
from pathlib import Path

from src.llm_client import OllamaClient, LLMError
from src.prompt_builder import _format_checklists
from src.findings_schema import AGENT_STEP_SCHEMA, normalize_finding
from src.audit_v2 import _verify, _numbered, _tally

MAX_STEPS = int(os.environ.get("AGENT_MAX_STEPS", "8"))
_SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "coverage"}
_READ_CAP = 400          # lines returned per read_file
_GREP_CAP = 40           # matches returned per grep


class Tools:
    """Read-only codebase access exposed to the agent."""

    def __init__(self, root: str):
        self.root = Path(root)

    def run(self, tool: str, args: dict) -> str:
        try:
            if tool == "read_file":
                return self._read(args.get("path", ""))
            if tool == "grep":
                return self._grep(args.get("pattern", ""))
            if tool == "get_symbol":
                return self._symbol(args.get("symbol", ""))
        except Exception as e:  # tool errors are observations, not crashes
            return f"tool error: {e}"
        return f"unknown tool: {tool}"

    def _resolve(self, rel: str) -> Path | None:
        p = (self.root / rel).resolve()
        if self.root.resolve() not in p.parents and p != self.root.resolve():
            return None  # keep the agent inside the codebase
        if p.is_file():
            return p
        matches = [m for m in self.root.glob(rel) if m.is_file()]
        return matches[0] if matches else None

    def _read(self, rel: str) -> str:
        p = self._resolve(rel)
        if not p:
            return f"file not found: {rel}"
        text = p.read_text(encoding="utf-8", errors="replace")
        lines = text.split("\n")
        body = _numbered("\n".join(lines[:_READ_CAP]), 1)
        more = f"\n... ({len(lines) - _READ_CAP} more lines)" if len(lines) > _READ_CAP else ""
        return f"{p.relative_to(self.root)}:\n{body}{more}"

    def _iter_ts(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in filenames:
                if name.endswith((".ts", ".tsx")):
                    yield Path(dirpath) / name

    def _grep(self, pattern: str) -> str:
        if not pattern:
            return "empty pattern"
        try:
            rx = re.compile(pattern)
        except re.error as e:
            return f"bad regex: {e}"
        hits = []
        for f in self._iter_ts():
            try:
                for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").split("\n"), 1):
                    if rx.search(line):
                        hits.append(f"{f.relative_to(self.root)}:{i}: {line.strip()[:160]}")
                        if len(hits) >= _GREP_CAP:
                            return "\n".join(hits) + f"\n... (capped at {_GREP_CAP})"
            except OSError:
                continue
        return "\n".join(hits) if hits else "no matches"

    def _symbol(self, symbol: str) -> str:
        if not symbol:
            return "empty symbol"
        rx = re.compile(rf"\b(function|const|class|type|interface)\s+{re.escape(symbol)}\b")
        for f in self._iter_ts():
            lines = f.read_text(encoding="utf-8", errors="replace").split("\n")
            for i, line in enumerate(lines):
                if rx.search(line):
                    snippet = _numbered("\n".join(lines[i:i + 60]), i + 1)
                    return f"{f.relative_to(self.root)} (definition):\n{snippet}"
        return f"definition of '{symbol}' not found"


_SYSTEM = (
    "You are a cryptographic security auditor for StenVault, a zero-knowledge encrypted "
    "storage system where the server never sees plaintext, filenames, or passwords. "
    "Investigate the target file for checklist violations. Use tools to follow imported "
    "helpers and cross-file data flow before concluding — do not guess at values defined "
    "elsewhere. When confident, return tool='done' with the findings array (empty if none). "
    "Never flag intentional zero-knowledge patterns (HKDF-derived IVs, wrapped extractable "
    "keys, HKDF domain separators)."
)


def audit_file(
    agent: OllamaClient,
    verifier: OllamaClient,
    file_path: str,
    rel_path: str,
    checklists: list[dict],
    stage: str,
    *,
    codebase_root: str,
    stats: dict | None = None,
    log=lambda *_: None,
) -> list[dict]:
    """Investigate one file agentically; return verified, triage-ready findings."""
    tools = Tools(codebase_root)
    seed_file = tools._read(rel_path)
    messages = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content":
            f"TARGET FILE: {rel_path}\n\n{seed_file}\n\n{_format_checklists(checklists)}\n\n"
            "Investigate now. Respond with one step at a time."},
    ]

    raw_findings: list[dict] = []
    for step in range(MAX_STEPS):
        try:
            step_out = agent.chat(messages, schema=AGENT_STEP_SCHEMA)
        except LLMError as e:
            log(f"    [red]agent error: {e}[/red]")
            break
        tool = step_out.get("tool", "done")
        thought = (step_out.get("thought") or "").strip()
        log(f"    step {step+1}: {tool} — {thought[:80]}")

        if tool == "done":
            raw_findings = step_out.get("findings") or []
            break

        observation = tools.run(tool, step_out.get("args") or {})
        messages.append({"role": "assistant", "content": f"{thought}\n[{tool}]"})
        messages.append({"role": "user", "content": f"OBSERVATION:\n{observation}"})
    else:
        log("    [yellow]max steps reached without done[/yellow]")

    findings = [
        normalize_finding(
            f, rel_path, stage,
            source="agentic", model=agent.cfg.model,
            finding_type="agentic",
        )
        for f in raw_findings
    ]
    log(f"    {len(findings)} raw findings")

    numbered = _numbered(Path(codebase_root, rel_path).read_text(encoding="utf-8", errors="replace"), 1)
    kept = _verify(verifier, rel_path, numbered, findings)
    _tally(stats, findings, kept)
    return kept
