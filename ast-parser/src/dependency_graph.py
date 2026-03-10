"""
Cross-file dependency graph for TypeScript codebases.
Builds import/export maps and traces parameter origins across file boundaries.
"""

import os
import re
from pathlib import Path
from dataclasses import dataclass, field

import tree_sitter_typescript as ts_typescript
from tree_sitter import Language, Parser, Node

TS_LANGUAGE = Language(ts_typescript.language_typescript())
_parser = Parser(TS_LANGUAGE)


@dataclass
class ExportedSymbol:
    name: str              # "encryptLargeSecretKey"
    file: str              # "apps/web/src/hooks/masterKeyCrypto.ts"
    line: int
    kind: str              # "function" | "const" | "class" | "re-export"
    params: list[str] = field(default_factory=list)
    source_snippet: str = ""


@dataclass
class ImportLink:
    importing_file: str
    imported_file: str
    symbols: list[str] = field(default_factory=list)
    line: int = 0


@dataclass
class CrossFileCallSite:
    caller_file: str
    caller_function: str
    caller_line: int
    callee_file: str
    callee_function: str
    arg_index: int = -1
    arg_expression: str = ""


@dataclass
class DependencyGraph:
    exports: dict[str, list[ExportedSymbol]] = field(default_factory=dict)
    imports: dict[str, list[ImportLink]] = field(default_factory=dict)
    call_sites: list[CrossFileCallSite] = field(default_factory=list)
    reverse_callers: dict[str, list[CrossFileCallSite]] = field(default_factory=dict)


# Path alias mappings for CloudVault
_ALIASES = {
    "@/": "apps/web/src/",
    "@cloudvault/shared/": "packages/shared/src/",
    "@cloudvault/shared": "packages/shared/src/index.ts",
}


def resolve_import_path(
    importing_file: str, import_specifier: str, codebase_root: str
) -> str | None:
    """
    Resolve a TypeScript import specifier to an actual file path (relative to codebase root).

    Handles:
    - Path aliases: @/ -> apps/web/src/, @cloudvault/shared -> packages/shared/src/
    - Relative imports: ./foo, ../lib/bar
    - Extension resolution: .ts, /index.ts
    """
    root = Path(codebase_root)

    # Resolve aliases
    resolved_spec = import_specifier
    for alias, target in _ALIASES.items():
        if import_specifier.startswith(alias):
            resolved_spec = target + import_specifier[len(alias):]
            break

    # Resolve relative imports
    if resolved_spec.startswith("."):
        importing_dir = str(Path(importing_file).parent)
        # Normalize path separators
        combined = os.path.normpath(os.path.join(importing_dir, resolved_spec))
        resolved_spec = combined.replace("\\", "/")

    # Try to find the actual file
    candidates = [
        resolved_spec,
        resolved_spec + ".ts",
        resolved_spec + ".tsx",
        resolved_spec + "/index.ts",
        resolved_spec + "/index.tsx",
    ]

    for candidate in candidates:
        full_path = root / candidate
        if full_path.exists():
            return candidate

    return None


def _parse_file_safe(file_path: Path) -> tuple[Node | None, bytes]:
    """Parse a TypeScript file, returning (root_node, source) or (None, b'') on error."""
    try:
        with open(file_path, "rb") as f:
            source = f.read()
        tree = _parser.parse(source)
        return tree.root_node, source
    except (OSError, UnicodeDecodeError):
        return None, b""


def extract_exports_ast(root: Node, source: bytes, file_path: str) -> list[ExportedSymbol]:
    """
    Extract all exported symbols from a TypeScript AST.

    Handles:
    - export function foo(...)
    - export const foo = ...
    - export { foo, bar } from '...'
    - export { foo, bar }
    - export default function/class/expression
    - export class Foo
    """
    exports = []

    for child in root.children:
        if child.type != "export_statement":
            continue

        line = child.start_point[0] + 1

        # export function foo(...) or export class Foo
        decl = child.child_by_field_name("declaration")
        if decl:
            if decl.type in ("function_declaration", "generator_function_declaration"):
                name_node = decl.child_by_field_name("name")
                if name_node:
                    name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
                    params = _extract_export_params(decl, source)
                    snippet = _get_snippet(source, decl, max_lines=5)
                    exports.append(ExportedSymbol(
                        name=name, file=file_path, line=line,
                        kind="function", params=params, source_snippet=snippet,
                    ))

            elif decl.type == "lexical_declaration":
                # export const foo = (...) => { ... }
                for vd in decl.children:
                    if vd.type == "variable_declarator":
                        name_node = vd.child_by_field_name("name")
                        value_node = vd.child_by_field_name("value")
                        if name_node:
                            name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
                            kind = "const"
                            params = []
                            if value_node and value_node.type in ("arrow_function", "function_expression"):
                                kind = "function"
                                params = _extract_export_params(value_node, source)
                            snippet = _get_snippet(source, vd, max_lines=5)
                            exports.append(ExportedSymbol(
                                name=name, file=file_path, line=line,
                                kind=kind, params=params, source_snippet=snippet,
                            ))

            elif decl.type == "class_declaration":
                name_node = decl.child_by_field_name("name")
                if name_node:
                    name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
                    exports.append(ExportedSymbol(
                        name=name, file=file_path, line=line,
                        kind="class", source_snippet=_get_snippet(source, decl, max_lines=3),
                    ))

            continue

        # export default
        default_node = None
        for ch in child.children:
            text = source[ch.start_byte:ch.end_byte].decode("utf-8", errors="replace")
            if text == "default":
                continue
            if ch.type not in ("export", ";", "default"):
                default_node = ch
                break

        if default_node:
            name = "default"
            if default_node.type in ("function_declaration", "generator_function_declaration"):
                fn_name = default_node.child_by_field_name("name")
                if fn_name:
                    name = source[fn_name.start_byte:fn_name.end_byte].decode("utf-8", errors="replace")
            exports.append(ExportedSymbol(
                name=name, file=file_path, line=line, kind="function",
                source_snippet=_get_snippet(source, default_node, max_lines=3),
            ))
            continue

        # export { foo, bar } or export { foo, bar } from '...'
        export_text = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
        brace_match = re.search(r'\{([^}]+)\}', export_text)
        from_match = re.search(r'from\s+["\']([^"\']+)["\']', export_text)

        if brace_match:
            names = [n.strip().split(" as ")[-1].strip() for n in brace_match.group(1).split(",")]
            kind = "re-export" if from_match else "function"
            for name in names:
                if name:
                    exports.append(ExportedSymbol(
                        name=name, file=file_path, line=line, kind=kind,
                    ))

    return exports


def _extract_export_params(fn_node: Node, source: bytes) -> list[str]:
    """Extract parameter names from a function-like node."""
    params = []
    params_node = fn_node.child_by_field_name("parameters")
    if params_node:
        for child in params_node.children:
            if child.type in ("required_parameter", "optional_parameter"):
                pattern = child.child_by_field_name("pattern")
                if pattern:
                    params.append(source[pattern.start_byte:pattern.end_byte].decode("utf-8", errors="replace"))
            elif child.type == "identifier":
                params.append(source[child.start_byte:child.end_byte].decode("utf-8", errors="replace"))
    return params


def _get_snippet(source: bytes, node: Node, max_lines: int = 5) -> str:
    """Get first N lines of a node's source."""
    text = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
    lines = text.split("\n")[:max_lines]
    return "\n".join(lines)


def _extract_imports_from_ast(root: Node, source: bytes, file_path: str, codebase_root: str) -> list[ImportLink]:
    """Extract all import statements and resolve their targets."""
    imports = []

    for child in root.children:
        if child.type != "import_statement":
            continue

        text = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
        line = child.start_point[0] + 1

        # Extract import specifier
        from_match = re.search(r'from\s+["\']([^"\']+)["\']', text)
        if not from_match:
            # import 'side-effect-module'
            continue

        specifier = from_match.group(1)

        # Skip node_modules imports (no ./ or @/ prefix that resolves to local)
        if not specifier.startswith(".") and not any(specifier.startswith(a) for a in _ALIASES):
            continue

        resolved = resolve_import_path(file_path, specifier, codebase_root)

        # Extract imported symbol names
        symbols = []
        brace_match = re.search(r'\{([^}]+)\}', text)
        if brace_match:
            for part in brace_match.group(1).split(","):
                part = part.strip()
                if " as " in part:
                    # import { foo as bar } -> track both
                    symbols.append(part.split(" as ")[-1].strip())
                elif part:
                    symbols.append(part)

        # Default import
        default_match = re.search(r'import\s+(\w+)\s+from', text)
        if default_match:
            symbols.append(default_match.group(1))

        imports.append(ImportLink(
            importing_file=file_path,
            imported_file=resolved or specifier,
            symbols=symbols,
            line=line,
        ))

    return imports


def find_cross_file_call_sites(
    root: Node, source: bytes, file_path: str,
    imported_symbols: dict[str, str],
    all_exports: dict[str, list[ExportedSymbol]],
) -> list[CrossFileCallSite]:
    """
    For each call_expression that invokes an imported symbol,
    record the caller function, callee, and argument expressions.

    imported_symbols: symbol_name -> source_file (resolved)
    """
    call_sites = []
    _walk_for_cross_file_calls(root, source, file_path, imported_symbols, all_exports, call_sites, None)
    return call_sites


def _walk_for_cross_file_calls(
    node: Node, source: bytes, file_path: str,
    imported_symbols: dict[str, str],
    all_exports: dict[str, list[ExportedSymbol]],
    results: list[CrossFileCallSite],
    current_function: str | None,
):
    """Recursively walk AST to find cross-file call sites."""
    # Track current function scope
    fn_name = current_function
    if node.type in ("function_declaration", "generator_function_declaration"):
        name_node = node.child_by_field_name("name")
        if name_node:
            fn_name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
    elif node.type == "variable_declarator":
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node and value_node and value_node.type in ("arrow_function", "function_expression"):
            fn_name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")

    if node.type == "call_expression":
        fn_node = node.child_by_field_name("function")
        if fn_node:
            fn_text = source[fn_node.start_byte:fn_node.end_byte].decode("utf-8", errors="replace")

            # Check if the called function is an imported symbol
            callee_name = fn_text.split("(")[0].strip()
            # Handle member access: obj.method -> check 'obj'
            if "." in callee_name:
                parts = callee_name.split(".")
                callee_name = parts[0]

            if callee_name in imported_symbols:
                callee_file = imported_symbols[callee_name]
                caller_line = node.start_point[0] + 1

                # Extract arguments
                args_node = node.child_by_field_name("arguments")
                if args_node:
                    arg_idx = 0
                    for arg_child in args_node.children:
                        if arg_child.type in ("(", ")", ","):
                            continue
                        arg_text = source[arg_child.start_byte:arg_child.end_byte].decode("utf-8", errors="replace")
                        results.append(CrossFileCallSite(
                            caller_file=file_path,
                            caller_function=fn_name or "<module>",
                            caller_line=caller_line,
                            callee_file=callee_file,
                            callee_function=callee_name,
                            arg_index=arg_idx,
                            arg_expression=arg_text[:200],
                        ))
                        arg_idx += 1
                else:
                    # Call with no args
                    results.append(CrossFileCallSite(
                        caller_file=file_path,
                        caller_function=fn_name or "<module>",
                        caller_line=node.start_point[0] + 1,
                        callee_file=callee_file,
                        callee_function=callee_name,
                    ))

    for child in node.children:
        _walk_for_cross_file_calls(child, source, file_path, imported_symbols, all_exports, results, fn_name)


def resolve_parameter_origin(
    graph: DependencyGraph,
    file_path: str,
    function_name: str,
    param_name: str,
    param_index: int,
    max_depth: int = 3,
    _depth: int = 0,
) -> list[dict]:
    """
    Given a parameter of a function, find all callers and trace what they pass as that argument.
    Returns a list of origin descriptions.

    Recursive up to max_depth to handle chains like A->B->C.
    """
    if _depth >= max_depth:
        return [{"origin": "max_depth_reached", "depth": _depth}]

    # Build callee key
    callee_key = f"{file_path}::{function_name}"
    call_sites = graph.reverse_callers.get(callee_key, [])

    if not call_sites:
        return [{"origin": "no_callers_found", "function": function_name, "file": file_path}]

    results = []
    for cs in call_sites:
        if cs.arg_index == param_index:
            arg = cs.arg_expression
            origin_info = {
                "caller_file": cs.caller_file,
                "caller_function": cs.caller_function,
                "caller_line": cs.caller_line,
                "arg_expression": arg,
            }

            # Classify the argument expression
            if re.search(r'getRandomValues|generateKey|crypto\.subtle\.generate', arg):
                origin_info["origin"] = "crypto_random"
                origin_info["via"] = arg[:100]
            elif re.search(r'deriveKey|deriveBits|hkdf|HKDF|deriveChunkIV', arg):
                origin_info["origin"] = "derived"
                origin_info["via"] = arg[:100]
            elif re.match(r'^["\']', arg.strip()):
                origin_info["origin"] = "hardcoded"
                origin_info["via"] = arg[:50]
            elif re.match(r'^\d+$', arg.strip()):
                origin_info["origin"] = "hardcoded"
                origin_info["via"] = arg
            elif re.match(r'^\w+$', arg.strip()):
                # Simple variable — might be a parameter of the caller, recurse
                origin_info["origin"] = "variable"
                origin_info["via"] = arg

                # Check if this variable is a parameter of the caller function
                # by looking at the caller's exports
                caller_exports = graph.exports.get(cs.caller_file, [])
                for exp in caller_exports:
                    if exp.name == cs.caller_function and arg in exp.params:
                        # It's a parameter of the caller — recurse
                        caller_param_idx = exp.params.index(arg)
                        deeper = resolve_parameter_origin(
                            graph, cs.caller_file, cs.caller_function,
                            arg, caller_param_idx, max_depth, _depth + 1,
                        )
                        origin_info["traced_deeper"] = deeper
                        break
            else:
                origin_info["origin"] = "expression"
                origin_info["via"] = arg[:100]

            results.append(origin_info)

    return results if results else [{"origin": "no_matching_arg_index", "param_index": param_index}]


def build_dependency_graph(
    codebase_root: str, target_files: list[str] | None = None
) -> DependencyGraph:
    """
    Build a cross-file dependency graph for the codebase.

    1. Parse all .ts files (or target_files subset)
    2. Extract exports from each file
    3. Extract imports and resolve paths
    4. Map cross-file call sites
    5. Build reverse caller index

    Args:
        codebase_root: Root path of the codebase
        target_files: Optional list of files to analyze (relative to root).
                      If None, scans all .ts files under common directories.
    """
    from rich.console import Console
    console = Console()

    graph = DependencyGraph()
    root_path = Path(codebase_root)

    # Collect files to analyze
    if target_files:
        ts_files = []
        for tf in target_files:
            fp = root_path / tf
            if fp.exists():
                ts_files.append(fp)
    else:
        # Scan common directories
        scan_dirs = ["apps", "packages", "src", "lib"]
        ts_files = []
        for scan_dir in scan_dirs:
            d = root_path / scan_dir
            if d.exists():
                ts_files.extend(d.rglob("*.ts"))
                ts_files.extend(d.rglob("*.tsx"))

    console.print(f"  [dim]Dependency graph: scanning {len(ts_files)} files...[/dim]")

    # Phase 1: Extract exports from all files
    for fp in ts_files:
        root_node, source = _parse_file_safe(fp)
        if root_node is None:
            continue

        rel_path = str(fp.relative_to(root_path)).replace("\\", "/")
        file_exports = extract_exports_ast(root_node, source, rel_path)
        if file_exports:
            graph.exports[rel_path] = file_exports

    console.print(f"  [dim]  → {sum(len(v) for v in graph.exports.values())} exports in {len(graph.exports)} files[/dim]")

    # Phase 2: Extract imports and resolve paths
    for fp in ts_files:
        root_node, source = _parse_file_safe(fp)
        if root_node is None:
            continue

        rel_path = str(fp.relative_to(root_path)).replace("\\", "/")
        file_imports = _extract_imports_from_ast(root_node, source, rel_path, codebase_root)
        if file_imports:
            graph.imports[rel_path] = file_imports

    total_imports = sum(len(v) for v in graph.imports.values())
    console.print(f"  [dim]  → {total_imports} import links[/dim]")

    # Phase 3: Find cross-file call sites
    # Build imported_symbols map per file: symbol_name -> source_file
    for fp in ts_files:
        root_node, source = _parse_file_safe(fp)
        if root_node is None:
            continue

        rel_path = str(fp.relative_to(root_path)).replace("\\", "/")
        file_imports = graph.imports.get(rel_path, [])

        # Build symbol -> source file mapping for this file
        imported_symbols: dict[str, str] = {}
        for imp in file_imports:
            for sym in imp.symbols:
                imported_symbols[sym] = imp.imported_file

        if imported_symbols:
            call_sites = find_cross_file_call_sites(
                root_node, source, rel_path, imported_symbols, graph.exports,
            )
            graph.call_sites.extend(call_sites)

    console.print(f"  [dim]  → {len(graph.call_sites)} cross-file call sites[/dim]")

    # Phase 4: Build reverse caller index
    for cs in graph.call_sites:
        callee_key = f"{cs.callee_file}::{cs.callee_function}"
        graph.reverse_callers.setdefault(callee_key, []).append(cs)

    console.print(f"  [dim]  → Dependency graph complete[/dim]")

    return graph


def graph_to_dict(graph: DependencyGraph) -> dict:
    """Serialize a DependencyGraph to a JSON-compatible dict (for caching/debugging)."""
    return {
        "exports": {
            file: [
                {
                    "name": e.name, "file": e.file, "line": e.line,
                    "kind": e.kind, "params": e.params,
                }
                for e in exports
            ]
            for file, exports in graph.exports.items()
        },
        "imports": {
            file: [
                {
                    "importing_file": i.importing_file,
                    "imported_file": i.imported_file,
                    "symbols": i.symbols, "line": i.line,
                }
                for i in imports
            ]
            for file, imports in graph.imports.items()
        },
        "call_sites_count": len(graph.call_sites),
        "reverse_callers_count": len(graph.reverse_callers),
    }
