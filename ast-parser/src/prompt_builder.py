"""
Build audit prompts for LLM-based crypto auditing.
Combines code chunks + crypto data flow traces + domain checklists into structured prompts.
Supports both checklist auditing and adversarial red-team analysis.
"""


def build_audit_prompt(
    chunk_content: str,
    chunk_start_line: int,
    chunk_end_line: int,
    functions: list[str],
    imports: list[str],
    crypto_traces: list[dict],
    checklists: list[dict],
    file_path: str,
    chunk_index: int,
    total_chunks: int,
    semgrep_hints: str = "",
    cross_file_context: str = "",
    type_signatures: str = "",
    design_doc_excerpt: str = "",
    few_shot_examples: str = "",
) -> str:
    """Build the complete audit prompt for one chunk."""

    # Format line-numbered code
    lines = chunk_content.split("\n")
    numbered = "\n".join(
        f"{chunk_start_line + i:>4} | {line}" for i, line in enumerate(lines)
    )

    # Format crypto traces
    trace_section = _format_traces(crypto_traces)

    # Format imports
    import_section = ""
    if imports:
        import_section = "IMPORTS RELEVANT TO THIS CHUNK:\n"
        for imp in imports[:10]:  # Limit to 10 most relevant
            import_section += f"  {imp}\n"

    # Format checklists
    checklist_section = _format_checklists(checklists)

    # Build enrichment sections
    enrichment = ""
    if semgrep_hints:
        enrichment += f"\n{semgrep_hints}\n"
    if cross_file_context:
        enrichment += f"\n{cross_file_context}\n"
    if type_signatures:
        enrichment += f"\n{type_signatures}\n"
    if design_doc_excerpt:
        enrichment += f"\nRELEVANT DESIGN CONTEXT:\n{design_doc_excerpt}\n"

    # Few-shot examples section
    examples_section = ""
    if few_shot_examples:
        examples_section = f"\n{few_shot_examples}\n"

    # Updated parameter rule when cross-file context is available
    param_rule = (
        "- If a variable comes from a PARAMETER and CROSS-FILE PARAMETER ORIGINS are provided above, "
        "use the traced origin to assess safety. If NO cross-file trace is available for a parameter, SKIP."
        if cross_file_context
        else "- If a variable comes from a PARAMETER (shown in traces), you CANNOT determine its safety from this chunk alone — SKIP."
    )

    return f"""You are a cryptographic security auditor reviewing a zero-knowledge encrypted cloud storage system (CloudVault). The server NEVER sees file content, filenames, or passwords.

FILE: {file_path}
CHUNK: {chunk_index}/{total_chunks} (lines {chunk_start_line}-{chunk_end_line})
FUNCTIONS: {', '.join(functions)}

{import_section}
{trace_section}
{enrichment}
{examples_section}

--- CODE START (lines {chunk_start_line}-{chunk_end_line}) ---
{numbered}
--- CODE END ---

{checklist_section}

INSTRUCTIONS:
1. For each checklist item, determine if the code in this chunk is COMPLIANT or has a VIOLATION.
2. Only report VIOLATIONS — items where the code fails the check.
3. If this chunk does not contain code relevant to a checklist item, SKIP it (do not report).
4. For each violation, provide the exact line range and evidence from the code.
5. Use the CRYPTO DATA FLOW TRACES to understand where IVs, keys, and salts originate — do not guess.
6. If STATIC ANALYSIS HINTS are provided, investigate those lines carefully — they are confirmed patterns.

OUTPUT FORMAT — respond ONLY with a JSON array (empty array [] if no violations found):
[
  {{
    "checklist_item": "C01",
    "severity": "critical",
    "line_start": 260,
    "line_end": 265,
    "finding": "Brief description of the violation",
    "evidence": "The exact code snippet showing the problem",
    "suggestion": "How to fix it"
  }}
]

CRITICAL RULES:
- Do NOT invent issues not supported by the actual code shown.
- Do NOT flag intentional design patterns as violations.
{param_rule}
- If there are NO violations, respond with exactly: []
- Respond ONLY with the JSON array, no explanation before or after.
"""


def build_adversarial_prompt(
    chunk_content: str,
    chunk_start_line: int,
    chunk_end_line: int,
    functions: list[str],
    imports: list[str],
    crypto_traces: list[dict],
    file_path: str,
    semgrep_hints: str = "",
    cross_file_context: str = "",
) -> str:
    """
    Build an adversarial red-team prompt for one chunk.
    Instead of checklist compliance, this asks "how would you break this?"
    """
    # Format line-numbered code
    lines = chunk_content.split("\n")
    numbered = "\n".join(
        f"{chunk_start_line + i:>4} | {line}" for i, line in enumerate(lines)
    )

    # Format crypto traces
    trace_section = _format_traces(crypto_traces)

    # Format imports
    import_section = ""
    if imports:
        import_section = "IMPORTS:\n"
        for imp in imports[:10]:
            import_section += f"  {imp}\n"

    # Build enrichment
    enrichment = ""
    if semgrep_hints:
        enrichment += f"\n{semgrep_hints}\n"
    if cross_file_context:
        enrichment += f"\n{cross_file_context}\n"

    return f"""You are a cryptographic attack researcher. Your goal is to find CONCRETE EXPLOITABLE attack vectors in this code.

This is a zero-knowledge encrypted cloud storage system. The server should NEVER see plaintext content, filenames, or passwords. Any violation of this property is critical.

FILE: {file_path}
FUNCTIONS: {', '.join(functions)}

{import_section}
{trace_section}
{enrichment}

--- CODE (lines {chunk_start_line}-{chunk_end_line}) ---
{numbered}
--- END ---

TASK: Find concrete attack vectors. For each attack, describe:
- The exact attack steps an adversary would take
- What preconditions are needed
- The impact if successful
- How exploitable it is in practice

Focus on:
1. Can an attacker recover plaintext? (key/IV reuse, weak KDF, missing auth)
2. Can an attacker forge or tamper data? (missing MAC, malleable ciphertext)
3. Can an attacker escalate privileges? (auth bypass, session issues)
4. Are there timing or side-channel leaks?
5. Can concurrent operations cause security failures? (race conditions on crypto state)

OUTPUT FORMAT — respond ONLY with a JSON array (empty array [] if no attacks found):
[
  {{
    "attack_vector": "Short name of the attack",
    "preconditions": "What the attacker needs",
    "impact": "What the attacker gains",
    "exploitability": "low|medium|high",
    "affected_lines": [45, 67],
    "evidence": "The exact code that enables this attack"
  }}
]

RULES:
- Only report attacks that are CONCRETE and supported by the code shown.
- Do NOT report theoretical attacks that require unrealistic assumptions.
- Do NOT repeat generic advice (e.g., "use HTTPS") — focus on this specific code.
- If there are NO attacks, respond with exactly: []
- Respond ONLY with the JSON array.
"""


def _format_traces(traces: list[dict]) -> str:
    """Format crypto data flow traces for the prompt."""
    if not traces:
        return "CRYPTO DATA FLOW TRACES:\n  (no crypto API calls detected in this chunk)\n"

    text = "CRYPTO DATA FLOW TRACES:\n"
    for i, t in enumerate(traces, 1):
        op = t.get("operation", "unknown")
        line = t.get("line", "?")
        text += f"  {i}. {op} @ line {line}:\n"

        if "algorithm" in t:
            text += f"     algorithm: {t['algorithm']}\n"

        for key in ("iv", "key", "salt", "wrapping_key"):
            if key in t:
                val = t[key]
                if isinstance(val, dict):
                    origin = val.get("origin", "unknown")
                    text += f"     {key}: {origin.upper()}"
                    via = val.get("via", "")
                    if via:
                        text += f" via {via}"
                    vline = val.get("line", 0)
                    if vline:
                        text += f" [line {vline}]"
                    text += "\n"
                else:
                    text += f"     {key}: {val}\n"

        if t.get("type") == "custom_helper":
            text += f"     (CloudVault custom helper — trace into its definition for details)\n"

    return text


def _format_checklists(checklists: list[dict]) -> str:
    """Format checklist items for the prompt."""
    text = "CHECKLIST — For each item, determine COMPLIANT or VIOLATION:\n"

    for cl in checklists:
        cid = cl.get("checklist_id", "unknown")
        text += f"\n[{cid}]\n"
        for item in cl.get("items", []):
            item_id = item.get("id", "?")
            severity = item.get("severity", "medium").upper()
            question = item.get("question", "")
            text += f"  {item_id} [{severity}]: {question}\n"

    return text
