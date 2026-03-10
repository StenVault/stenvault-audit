"""
Data flow tracing for cryptographic variables.
Traces IV, key, and salt origins back to their source (random, derived, parameter, hardcoded).
"""

import re
from dataclasses import dataclass
from tree_sitter import Node

import tree_sitter_typescript as ts_typescript
from tree_sitter import Language, Parser

TS_LANGUAGE = Language(ts_typescript.language_typescript())
_parser = Parser(TS_LANGUAGE)


@dataclass
class VariableOrigin:
    type: str  # "crypto_random" | "derived" | "parameter" | "hardcoded" | "imported" | "computed" | "unknown"
    line: int = 0
    via: str = ""
    chain: list[str] | None = None
    value_preview: str = ""


def trace_variable_origin(var_name: str, scope_source: str, scope_start_line: int = 1) -> VariableOrigin:
    """
    Trace a variable backwards to find its origin within a scope.
    Looks for assignment patterns and classifies the source.
    """
    lines = scope_source.split("\n")

    for i, line in enumerate(lines):
        stripped = line.strip()
        actual_line = scope_start_line + i

        # const varName = crypto.getRandomValues(...)
        if re.search(rf'\b{re.escape(var_name)}\s*=\s*.*getRandomValues', stripped):
            return VariableOrigin(
                type="crypto_random",
                line=actual_line,
                via="crypto.getRandomValues",
            )

        # const varName = new Uint8Array(N)  followed by getRandomValues
        if re.search(rf'\b{re.escape(var_name)}\s*=\s*new\s+Uint8Array', stripped):
            # Check next few lines for getRandomValues(varName)
            for j in range(i + 1, min(i + 5, len(lines))):
                if f"getRandomValues({var_name})" in lines[j] or f"getRandomValues( {var_name}" in lines[j]:
                    return VariableOrigin(
                        type="crypto_random",
                        line=actual_line,
                        via="crypto.getRandomValues (filled after allocation)",
                    )

        # const varName = deriveChunkIV(...) or hkdf(...) or deriveBits(...)
        derive_match = re.search(
            rf'\b{re.escape(var_name)}\s*=\s*(?:await\s+)?(deriveChunkIV|hkdf|deriveBits|deriveKey|HKDF)\s*\(',
            stripped,
        )
        if derive_match:
            return VariableOrigin(
                type="derived",
                line=actual_line,
                via=derive_match.group(1),
                chain=[derive_match.group(1)],
            )

        # const varName = await crypto.subtle.deriveKey/deriveBits(...)
        subtle_derive = re.search(
            rf'\b{re.escape(var_name)}\s*=\s*(?:await\s+)?crypto\.subtle\.(deriveKey|deriveBits)\s*\(',
            stripped,
        )
        if subtle_derive:
            return VariableOrigin(
                type="derived",
                line=actual_line,
                via=f"crypto.subtle.{subtle_derive.group(1)}",
                chain=[f"subtle.{subtle_derive.group(1)}"],
            )

        # const varName = await crypto.subtle.importKey(...)
        import_match = re.search(
            rf'\b{re.escape(var_name)}\s*=\s*(?:await\s+)?crypto\.subtle\.importKey\s*\(',
            stripped,
        )
        if import_match:
            return VariableOrigin(
                type="imported_key",
                line=actual_line,
                via="crypto.subtle.importKey",
            )

        # const varName = await crypto.subtle.generateKey(...)
        gen_match = re.search(
            rf'\b{re.escape(var_name)}\s*=\s*(?:await\s+)?crypto\.subtle\.generateKey\s*\(',
            stripped,
        )
        if gen_match:
            return VariableOrigin(
                type="crypto_random",
                line=actual_line,
                via="crypto.subtle.generateKey",
            )

        # Hardcoded string/number
        hardcoded_match = re.search(
            rf'\b{re.escape(var_name)}\s*=\s*(["\'][^"\']*["\']|\d+)\s*[;\n]',
            stripped,
        )
        if hardcoded_match:
            return VariableOrigin(
                type="hardcoded",
                line=actual_line,
                value_preview=hardcoded_match.group(1)[:50],
            )

        # Generic assignment: const varName = someFunction(...)
        generic_match = re.search(
            rf'\b{re.escape(var_name)}\s*=\s*(?:await\s+)?(\w[\w.]*)\s*\(',
            stripped,
        )
        if generic_match:
            return VariableOrigin(
                type="computed",
                line=actual_line,
                via=generic_match.group(1),
            )

    # Check if var_name is a function parameter
    # Look for it in the first line (function signature)
    first_line = lines[0] if lines else ""
    if re.search(rf'[\(,]\s*{re.escape(var_name)}\s*[,:)\[]', first_line):
        return VariableOrigin(
            type="parameter",
            line=scope_start_line,
        )

    return VariableOrigin(type="unknown")


def trace_variable_origin_cross_file(
    var_name: str,
    scope_source: str,
    scope_start_line: int,
    function_name: str,
    file_path: str,
    graph=None,
) -> VariableOrigin:
    """
    Wrapper around trace_variable_origin that adds cross-file resolution.

    If the local trace result is "parameter" and a dependency graph is available,
    follows callers across files to find the actual origin.
    """
    origin = trace_variable_origin(var_name, scope_source, scope_start_line)

    if origin.type == "parameter" and graph is not None:
        try:
            from src.dependency_graph import resolve_parameter_origin

            # Find param index from exports
            file_exports = graph.exports.get(file_path, [])
            for exp in file_exports:
                if exp.name == function_name and var_name in exp.params:
                    param_idx = exp.params.index(var_name)
                    callers = resolve_parameter_origin(
                        graph, file_path, function_name, var_name, param_idx,
                    )
                    if callers and callers[0].get("origin") not in ("no_callers_found", "max_depth_reached", "no_matching_arg_index"):
                        caller = callers[0]
                        caller_origin = caller.get("origin", "unknown")
                        caller_via = caller.get("via", "")
                        caller_file = caller.get("caller_file", "")
                        caller_fn = caller.get("caller_function", "")
                        caller_line = caller.get("caller_line", 0)
                        via_desc = f"{caller_origin} via {caller_via}" if caller_via else caller_origin
                        return VariableOrigin(
                            type=caller_origin if caller_origin in ("crypto_random", "derived", "hardcoded") else "parameter",
                            line=caller_line,
                            via=f"{via_desc} in {caller_fn}() @ {caller_file}:{caller_line}",
                            chain=[f"param:{var_name}", f"caller:{caller_fn}@{caller_file}"],
                        )
                    break
        except ImportError:
            pass

    return origin


def trace_crypto_data_flow(
    chunk_content: str, chunk_start_line: int, file_path: str, graph=None
) -> list[dict]:
    """
    For each crypto operation in a chunk, trace the origin of key variables (IV, key, salt).
    Returns structured traces for the prompt builder.
    """
    traces = []
    lines = chunk_content.split("\n")

    for i, line in enumerate(lines):
        actual_line = chunk_start_line + i
        stripped = line.strip()

        # Detect crypto.subtle.encrypt/decrypt calls
        encrypt_match = re.search(r'crypto\.subtle\.(encrypt|decrypt)\s*\(', stripped)
        if encrypt_match:
            operation = encrypt_match.group(1)
            trace = {
                "operation": operation,
                "line": actual_line,
                "file": file_path,
            }

            # Try to find the algorithm object (look backwards for { name: 'AES-GCM', iv ... })
            iv_trace = _find_iv_in_context(lines, i, chunk_start_line)
            key_trace = _find_key_in_context(lines, i, chunk_start_line, chunk_content)

            trace["iv"] = iv_trace
            trace["key"] = key_trace

            # Look for algorithm name
            alg = _find_algorithm_name(lines, i)
            trace["algorithm"] = alg

            traces.append(trace)

        # Detect wrapKey/unwrapKey
        wrap_match = re.search(r'crypto\.subtle\.(wrapKey|unwrapKey)\s*\(', stripped)
        if wrap_match:
            trace = {
                "operation": wrap_match.group(1),
                "line": actual_line,
                "file": file_path,
            }
            key_trace = _find_key_in_context(lines, i, chunk_start_line, chunk_content)
            trace["wrapping_key"] = key_trace
            traces.append(trace)

        # Detect HKDF / deriveBits / deriveKey
        derive_match = re.search(r'crypto\.subtle\.(deriveKey|deriveBits)\s*\(', stripped)
        if derive_match:
            trace = {
                "operation": derive_match.group(1),
                "line": actual_line,
                "file": file_path,
            }
            salt_trace = _find_salt_in_context(lines, i, chunk_start_line, chunk_content)
            trace["salt"] = salt_trace
            traces.append(trace)

        # Detect custom helpers
        helper_match = re.search(
            r'(?:await\s+)?(deriveChunkIV|encryptLargeSecretKey|decryptLargeSecretKey|'
            r'encryptFilename|decryptFilename)\s*\(',
            stripped,
        )
        if helper_match:
            trace = {
                "operation": helper_match.group(1),
                "line": actual_line,
                "file": file_path,
                "type": "custom_helper",
            }
            traces.append(trace)

    return traces


def _find_iv_in_context(lines: list[str], call_line_idx: int, start_line: int) -> dict:
    """Look backwards from a crypto call to find the IV variable and trace its origin."""
    # Common patterns: { name: 'AES-GCM', iv: someVar } or { iv }
    search_range = lines[max(0, call_line_idx - 10):call_line_idx + 3]
    search_text = "\n".join(search_range)

    # Look for iv: varName or iv,
    iv_match = re.search(r'\biv\s*:\s*(\w+)', search_text)
    if iv_match:
        iv_var = iv_match.group(1)
        scope_text = "\n".join(lines[:call_line_idx + 1])
        origin = trace_variable_origin(iv_var, scope_text, start_line)
        return {
            "var": iv_var,
            "origin": origin.type,
            "line": origin.line,
            "via": origin.via,
        }

    # Shorthand: { iv } means iv: iv
    if re.search(r'[\{,]\s*iv\s*[,\}]', search_text):
        scope_text = "\n".join(lines[:call_line_idx + 1])
        origin = trace_variable_origin("iv", scope_text, start_line)
        return {
            "var": "iv",
            "origin": origin.type,
            "line": origin.line,
            "via": origin.via,
        }

    return {"var": "unknown", "origin": "unknown"}


def _find_key_in_context(
    lines: list[str], call_line_idx: int, start_line: int, full_content: str
) -> dict:
    """Look for the key variable used in a crypto call."""
    # In crypto.subtle.encrypt(algorithm, KEY, data) - key is the second argument
    call_line = lines[call_line_idx]

    # Try to find key variable name near the call
    # Common: crypto.subtle.encrypt(algo, keyVar, data)
    key_match = re.search(r'(?:encrypt|decrypt|wrapKey|unwrapKey)\s*\([^,]+,\s*(\w+)', call_line)
    if key_match:
        key_var = key_match.group(1)
        scope_text = "\n".join(lines[:call_line_idx + 1])
        origin = trace_variable_origin(key_var, scope_text, start_line)
        return {
            "var": key_var,
            "origin": origin.type,
            "line": origin.line,
            "via": origin.via,
        }

    return {"var": "unknown", "origin": "unknown"}


def _find_salt_in_context(
    lines: list[str], call_line_idx: int, start_line: int, full_content: str
) -> dict:
    """Look for salt variable in HKDF/derive context."""
    search_range = lines[max(0, call_line_idx - 10):call_line_idx + 5]
    search_text = "\n".join(search_range)

    salt_match = re.search(r'\bsalt\s*:\s*(\w+)', search_text)
    if salt_match:
        salt_var = salt_match.group(1)
        scope_text = "\n".join(lines[:call_line_idx + 1])
        origin = trace_variable_origin(salt_var, scope_text, start_line)
        return {
            "var": salt_var,
            "origin": origin.type,
            "line": origin.line,
            "via": origin.via,
        }

    return {"var": "unknown", "origin": "unknown"}


def _find_algorithm_name(lines: list[str], call_line_idx: int) -> str:
    """Extract algorithm name from nearby context."""
    search_range = lines[max(0, call_line_idx - 8):call_line_idx + 3]
    search_text = "\n".join(search_range)

    alg_match = re.search(r"name\s*:\s*['\"](\w[\w-]*)['\"]", search_text)
    if alg_match:
        return alg_match.group(1)
    return "unknown"
