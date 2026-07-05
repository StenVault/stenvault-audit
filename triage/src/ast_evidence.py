"""
Layer 1.5: AST-based evidence verification.
Parses the actual source file with tree-sitter and verifies that findings
reference real code constructs at the claimed line numbers.
"""

import re
from pathlib import Path

import tree_sitter_typescript as ts_typescript
from tree_sitter import Language, Parser, Node

TS_LANGUAGE = Language(ts_typescript.language_typescript())
_parser = Parser(TS_LANGUAGE)


def verify_evidence_ast(findings: list[dict], codebase_root: str) -> list[dict]:
    """
    For each finding, parse the referenced file with tree-sitter and verify
    that the claimed line range contains relevant code constructs.

    Sets evidence_quality: "exact" | "fuzzy" | "no_match"
    """
    # Cache parsed files
    file_cache: dict[str, tuple[Node | None, list[str], bytes]] = {}

    for f in findings:
        # Skip already-rejected findings
        status = f.get("triage_status", "")
        if status == "rejected":
            continue

        file_path = Path(codebase_root) / f.get("file", "")
        if not file_path.exists():
            f["evidence_quality"] = "no_match"
            continue

        # Parse file (cached)
        file_key = str(file_path)
        if file_key not in file_cache:
            try:
                with open(file_path, "rb") as fh:
                    source = fh.read()
                root = _parser.parse(source).root_node
                lines = source.decode("utf-8", errors="replace").split("\n")
                file_cache[file_key] = (root, lines, source)
            except (OSError, UnicodeDecodeError):
                file_cache[file_key] = (None, [], b"")

        root, lines, source = file_cache[file_key]
        if root is None:
            f["evidence_quality"] = "no_match"
            continue

        line_start = f.get("line_start", 0)
        line_end = f.get("line_end", 0)
        evidence = f.get("evidence", "")
        checklist_item = f.get("checklist_item", "")

        # Verify 1: Check that lines exist
        if line_start < 1 or line_end > len(lines):
            f["evidence_quality"] = "no_match"
            f["evidence_detail"] = "lines_out_of_range"
            continue

        # Get actual source at claimed lines
        actual_lines = lines[max(0, line_start - 1):line_end]
        actual_text = "\n".join(actual_lines)

        # Verify 2: Check if evidence text matches actual source
        if evidence:
            evidence_normalized = _normalize(evidence)
            actual_normalized = _normalize(actual_text)

            if evidence_normalized in actual_normalized:
                f["evidence_quality"] = "exact"
                continue

            # Try fuzzy match: check nearby lines (±5)
            expanded_start = max(0, line_start - 6)
            expanded_end = min(len(lines), line_end + 5)
            expanded_text = "\n".join(lines[expanded_start:expanded_end])
            expanded_normalized = _normalize(expanded_text)

            if evidence_normalized in expanded_normalized:
                f["evidence_quality"] = "fuzzy"
                f["evidence_detail"] = "matched_nearby"
                continue

            # Try matching key tokens from evidence
            key_tokens = _extract_key_tokens(evidence)
            if key_tokens and _tokens_match(key_tokens, expanded_normalized):
                f["evidence_quality"] = "fuzzy"
                f["evidence_detail"] = "key_tokens_matched"
                continue

        # Verify 3: Check if the right kind of code is at the claimed line
        # Use tree-sitter to check for crypto-relevant nodes
        quality = _verify_construct_at_line(root, line_start, checklist_item, source_bytes=source)
        f["evidence_quality"] = quality

    return findings


def _normalize(text: str) -> str:
    """Normalize whitespace for comparison."""
    return " ".join(text.split()).lower()


def _extract_key_tokens(evidence: str) -> list[str]:
    """Extract significant tokens from evidence text."""
    # Keep identifiers, function names, crypto API calls
    tokens = re.findall(r'[a-zA-Z_]\w{2,}', evidence)
    # Filter out common noise words
    noise = {"const", "let", "var", "await", "async", "function", "return", "new", "true", "false"}
    return [t for t in tokens if t not in noise]


def _tokens_match(tokens: list[str], text: str) -> bool:
    """Check if a majority of key tokens appear in the text."""
    if not tokens:
        return False
    matches = sum(1 for t in tokens if t.lower() in text)
    return matches / len(tokens) >= 0.6


def _verify_construct_at_line(
    root: Node, line: int, checklist_item: str, source_bytes: bytes
) -> str:
    """
    Check if there's a relevant code construct at the given line number.
    Uses tree-sitter to verify the AST node type.
    """
    # Convert to 0-based line index
    target_line = line - 1

    # Find the AST node at this line
    node = _find_node_at_line(root, target_line)
    if node is None:
        return "no_match"

    node_text = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace").lower()

    # Check if the node is crypto-relevant based on checklist category
    if checklist_item and checklist_item.startswith("C"):
        # Crypto checklist — look for crypto.subtle, encrypt, decrypt, IV, key, etc.
        crypto_indicators = ["crypto", "encrypt", "decrypt", "iv", "key", "gcm", "aes", "hkdf", "derive"]
        if any(ind in node_text for ind in crypto_indicators):
            return "fuzzy"

    elif checklist_item and checklist_item.startswith("KD"):
        # Key derivation
        kd_indicators = ["derive", "argon", "pbkdf", "hkdf", "salt", "key"]
        if any(ind in node_text for ind in kd_indicators):
            return "fuzzy"

    elif checklist_item and checklist_item.startswith("KL"):
        # Key lifecycle
        kl_indicators = ["key", "generate", "wrap", "unwrap", "export", "import", "extractable", "clear", "fill"]
        if any(ind in node_text for ind in kl_indicators):
            return "fuzzy"

    # Generic check: any function call or assignment at the line
    if node.type in ("call_expression", "assignment_expression", "variable_declarator", "lexical_declaration"):
        return "fuzzy"

    return "no_match"


def _find_node_at_line(root: Node, target_line: int) -> Node | None:
    """Find the most specific AST node starting at or containing the target line."""
    best = None

    def walk(node: Node):
        nonlocal best
        if node.start_point[0] <= target_line <= node.end_point[0]:
            # This node contains the target line — prefer more specific (deeper) nodes
            if node.type not in ("program", "statement_block", "export_statement"):
                best = node
            for child in node.children:
                walk(child)

    walk(root)
    return best
