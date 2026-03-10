"""
Context enrichment for audit prompts.
Adds cross-file type signatures, design doc excerpts, and resolved parameter origins.
"""

import re
from pathlib import Path


def get_type_signatures_for_chunk(
    chunk_content: str,
    graph,
    file_path: str,
    imports: list[str],
) -> list[dict]:
    """
    For each imported function called in the chunk, look up its signature in the dependency graph.

    Returns list of dicts: {"name": "encryptLargeSecretKey", "file": "...", "params": [...], "snippet": "..."}
    """
    if graph is None:
        return []

    signatures = []
    seen = set()

    # Extract function names called in the chunk
    called_names = set(re.findall(r'\b(\w+)\s*\(', chunk_content))

    # Check which called names are imported
    imported_names = set()
    for imp in imports:
        brace_match = re.search(r'\{([^}]+)\}', imp)
        if brace_match:
            for part in brace_match.group(1).split(","):
                name = part.strip().split(" as ")[-1].strip()
                if name:
                    imported_names.add(name)
        default_match = re.search(r'import\s+(\w+)\s+from', imp)
        if default_match:
            imported_names.add(default_match.group(1))

    # Find signatures for imported + called functions
    target_names = called_names & imported_names

    for export_file, export_list in graph.exports.items():
        for exp in export_list:
            if exp.name in target_names and exp.name not in seen:
                seen.add(exp.name)
                signatures.append({
                    "name": exp.name,
                    "file": exp.file,
                    "line": exp.line,
                    "params": exp.params,
                    "snippet": exp.source_snippet,
                })

    return signatures


def get_relevant_design_doc(
    chunk_content: str,
    crypto_traces: list[dict],
    design_docs_dir: str,
) -> str:
    """
    Find the most relevant section from design docs based on keywords in the chunk.
    Returns a short excerpt (<500 chars) or empty string.
    """
    docs_path = Path(design_docs_dir)
    if not docs_path.exists():
        return ""

    # Build keyword set from chunk content and crypto traces
    keywords = set()

    # Extract crypto-related keywords
    crypto_patterns = [
        r'AES[-_]?GCM', r'HKDF', r'Argon2', r'ML[-_]?KEM', r'X25519',
        r'Ed25519', r'ML[-_]?DSA', r'OPAQUE', r'JWT', r'TOTP',
        r'masterKey', r'wrapKey', r'unwrapKey', r'deriveKey',
        r'encrypt\w*', r'decrypt\w*', r'sign\w*', r'verify\w*',
        r'presigned', r'Shamir', r'recovery',
    ]
    for pattern in crypto_patterns:
        matches = re.findall(pattern, chunk_content, re.IGNORECASE)
        keywords.update(m.lower() for m in matches)

    # Add operation types from traces
    for trace in crypto_traces:
        op = trace.get("operation", "")
        if op:
            keywords.add(op.lower())

    if not keywords:
        return ""

    # Search design docs for best matching section
    best_section = ""
    best_score = 0

    for md_file in docs_path.glob("*.md"):
        try:
            content = md_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Split by ## headers
        sections = re.split(r'(?=^## )', content, flags=re.MULTILINE)

        for section in sections:
            if len(section.strip()) < 20:
                continue

            section_lower = section.lower()
            score = sum(1 for kw in keywords if kw in section_lower)

            if score > best_score:
                best_score = score
                # Take first 500 chars of the best section
                best_section = section.strip()[:500]

    return best_section


def resolve_all_parameter_origins_for_chunk(
    crypto_traces: list[dict],
    file_path: str,
    graph,
) -> list[dict]:
    """
    For each crypto trace with origin=parameter, resolve the parameter origin
    using the dependency graph.

    Returns list of resolved origins with context.
    """
    if graph is None:
        return []

    from src.dependency_graph import resolve_parameter_origin

    resolved = []

    for trace in crypto_traces:
        for key in ("iv", "key", "salt", "wrapping_key"):
            val = trace.get(key)
            if not isinstance(val, dict):
                continue
            if val.get("origin") != "parameter":
                continue

            var_name = val.get("var", "unknown")

            # Find the function this parameter belongs to
            # Look at exports for the file
            file_exports = graph.exports.get(file_path, [])
            for exp in file_exports:
                if var_name in exp.params:
                    param_idx = exp.params.index(var_name)
                    origins = resolve_parameter_origin(
                        graph, file_path, exp.name, var_name, param_idx,
                    )
                    resolved.append({
                        "trace_operation": trace.get("operation", "unknown"),
                        "trace_line": trace.get("line", 0),
                        "parameter": var_name,
                        "function": exp.name,
                        "callers": origins,
                    })
                    break

    return resolved


def format_cross_file_context(resolved_origins: list[dict]) -> str:
    """Format resolved parameter origins for prompt injection."""
    if not resolved_origins:
        return ""

    lines = ["CROSS-FILE PARAMETER ORIGINS (traced via dependency graph):"]
    for r in resolved_origins:
        lines.append(
            f"  - {r['function']}({r['parameter']}) @ {r['trace_operation']} line {r['trace_line']}:"
        )
        for caller in r.get("callers", []):
            origin = caller.get("origin", "unknown")
            via = caller.get("via", "")
            caller_file = caller.get("caller_file", "?")
            caller_fn = caller.get("caller_function", "?")
            caller_line = caller.get("caller_line", "?")
            lines.append(
                f"    → Called from {caller_fn}() in {caller_file}:{caller_line}"
                f" — arg is {origin.upper()}{f' via {via}' if via else ''}"
            )

            # Show deeper traces if available
            deeper = caller.get("traced_deeper", [])
            for d in deeper:
                d_origin = d.get("origin", "unknown")
                d_via = d.get("via", "")
                d_file = d.get("caller_file", "?")
                d_line = d.get("caller_line", "?")
                lines.append(
                    f"      → Deeper: {d_file}:{d_line} — {d_origin.upper()}"
                    f"{f' via {d_via}' if d_via else ''}"
                )

    return "\n".join(lines) + "\n"


def format_type_signatures(signatures: list[dict]) -> str:
    """Format cross-file type signatures for prompt injection."""
    if not signatures:
        return ""

    lines = ["IMPORTED FUNCTION SIGNATURES (from dependency graph):"]
    for sig in signatures:
        params_str = ", ".join(sig.get("params", []))
        lines.append(f"  - {sig['name']}({params_str}) — from {sig['file']}:{sig.get('line', '?')}")
        snippet = sig.get("snippet", "")
        if snippet:
            # Show first 2 lines of snippet
            snippet_lines = snippet.split("\n")[:2]
            for sl in snippet_lines:
                lines.append(f"    {sl.strip()}")

    return "\n".join(lines) + "\n"
