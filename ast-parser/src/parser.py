"""
Tree-sitter TypeScript parser for CloudVault crypto audit.
Provides AST-aware semantic chunking, crypto API detection, and call graph analysis.
"""

import re
from pathlib import Path
from dataclasses import dataclass, field

import tree_sitter_typescript as ts_typescript
from tree_sitter import Language, Parser, Node

TS_LANGUAGE = Language(ts_typescript.language_typescript())
_parser = Parser(TS_LANGUAGE)


@dataclass
class FunctionInfo:
    name: str
    start_line: int
    end_line: int
    node: Node
    source: str
    params: list[str] = field(default_factory=list)


@dataclass
class CryptoCall:
    method: str
    line: int
    text: str
    file: str
    args_text: list[str] = field(default_factory=list)


@dataclass
class Chunk:
    file: str
    line_start: int
    line_end: int
    functions: list[str]
    content: str
    crypto_calls: list[dict] = field(default_factory=list)


def parse_source(source: bytes) -> Node:
    """Parse TypeScript source into AST."""
    tree = _parser.parse(source)
    return tree.root_node


def parse_file(file_path: str) -> tuple[Node, bytes]:
    """Parse a TypeScript file and return root node + source bytes."""
    with open(file_path, "rb") as f:
        source = f.read()
    return parse_source(source), source


def extract_functions(root: Node, source: bytes) -> list[FunctionInfo]:
    """Extract all function declarations (named, arrow, class methods) with line ranges."""
    functions = []
    _walk_for_functions(root, source, functions)
    return functions


def _walk_for_functions(node: Node, source: bytes, results: list[FunctionInfo], depth: int = 0):
    """Recursively walk AST to find function-like nodes."""
    # Only extract top-level and first-level nested (exports)
    if depth > 2:
        return

    if node.type in ("function_declaration", "generator_function_declaration"):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
            params = _extract_params(node, source)
            results.append(FunctionInfo(
                name=name,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                node=node,
                source=source[node.start_byte:node.end_byte].decode("utf-8", errors="replace"),
                params=params,
            ))
            return  # Don't recurse into function body for nested functions

    if node.type == "lexical_declaration":
        # const foo = (...) => { ... }  or  const foo = async (...) => { ... }
        for child in node.children:
            if child.type == "variable_declarator":
                name_node = child.child_by_field_name("name")
                value_node = child.child_by_field_name("value")
                if name_node and value_node and value_node.type in ("arrow_function", "function_expression"):
                    name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
                    # Use the full declaration node for source
                    params = _extract_params(value_node, source)
                    results.append(FunctionInfo(
                        name=name,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        node=node,
                        source=source[node.start_byte:node.end_byte].decode("utf-8", errors="replace"),
                        params=params,
                    ))
                    return

    if node.type == "export_statement":
        # export function foo() or export const foo = ...
        decl = node.child_by_field_name("declaration")
        if decl:
            _walk_for_functions(decl, source, results, depth)
            # Fix the source to include the export keyword
            if results and results[-1].node == decl:
                results[-1].start_line = node.start_point[0] + 1
                results[-1].source = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
        return

    if node.type == "class_declaration":
        # Extract methods from classes
        class_name_node = node.child_by_field_name("name")
        class_name = ""
        if class_name_node:
            class_name = source[class_name_node.start_byte:class_name_node.end_byte].decode("utf-8", errors="replace")
        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                if child.type == "method_definition":
                    method_name_node = child.child_by_field_name("name")
                    if method_name_node:
                        method_name = source[method_name_node.start_byte:method_name_node.end_byte].decode("utf-8", errors="replace")
                        full_name = f"{class_name}.{method_name}" if class_name else method_name
                        params = _extract_params(child, source)
                        results.append(FunctionInfo(
                            name=full_name,
                            start_line=child.start_point[0] + 1,
                            end_line=child.end_point[0] + 1,
                            node=child,
                            source=source[child.start_byte:child.end_byte].decode("utf-8", errors="replace"),
                            params=params,
                        ))
        return

    # Recurse into children
    for child in node.children:
        _walk_for_functions(child, source, results, depth + 1)


def _extract_params(fn_node: Node, source: bytes) -> list[str]:
    """Extract parameter names from a function node."""
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


def extract_imports(root: Node, source: bytes) -> list[dict]:
    """Extract all import statements."""
    imports = []
    for child in root.children:
        if child.type == "import_statement":
            text = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
            imports.append({
                "text": text.strip(),
                "line": child.start_point[0] + 1,
            })
    return imports


def find_crypto_calls(root: Node, source: bytes, file_path: str = "") -> list[CryptoCall]:
    """Find all cryptographic API calls in the AST."""
    calls = []
    _walk_for_crypto_calls(root, source, file_path, calls)
    return calls


def _walk_for_crypto_calls(node: Node, source: bytes, file_path: str, results: list[CryptoCall]):
    """Recursively find crypto-related calls."""
    if node.type == "call_expression":
        fn_node = node.child_by_field_name("function")
        if fn_node:
            fn_text = source[fn_node.start_byte:fn_node.end_byte].decode("utf-8", errors="replace")

            # crypto.subtle.* calls
            if re.match(r"crypto\.subtle\.\w+", fn_text):
                method = fn_text.split(".")[-1]
                if method in (
                    "encrypt", "decrypt", "deriveKey", "deriveBits",
                    "importKey", "exportKey", "generateKey",
                    "sign", "verify", "wrapKey", "unwrapKey",
                    "digest",
                ):
                    args = _extract_call_args(node, source)
                    results.append(CryptoCall(
                        method=method,
                        line=node.start_point[0] + 1,
                        text=source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")[:200],
                        file=file_path,
                        args_text=args,
                    ))

            # crypto.getRandomValues
            elif fn_text == "crypto.getRandomValues":
                results.append(CryptoCall(
                    method="getRandomValues",
                    line=node.start_point[0] + 1,
                    text=source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")[:200],
                    file=file_path,
                ))

            # CloudVault custom crypto helpers
            elif re.match(
                r"(deriveChunkIV|encryptLargeSecretKey|decryptLargeSecretKey|"
                r"encryptFilename|decryptFilename|argon2id|hkdf|"
                r"encryptFileChunk|decryptFileChunk|"
                r"encryptHybrid|decryptHybrid|"
                r"wrapKey|unwrapKey|keyWrap)",
                fn_text,
            ):
                args = _extract_call_args(node, source)
                results.append(CryptoCall(
                    method=fn_text,
                    line=node.start_point[0] + 1,
                    text=source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")[:200],
                    file=file_path,
                    args_text=args,
                ))

            # Await expressions wrapping crypto calls
            elif fn_text.endswith((".encrypt", ".decrypt", ".sign", ".verify")):
                method = fn_text.split(".")[-1]
                results.append(CryptoCall(
                    method=method,
                    line=node.start_point[0] + 1,
                    text=source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")[:200],
                    file=file_path,
                ))

    # Recurse
    for child in node.children:
        _walk_for_crypto_calls(child, source, file_path, results)


def _extract_call_args(call_node: Node, source: bytes) -> list[str]:
    """Extract argument text from a call expression."""
    args = []
    args_node = call_node.child_by_field_name("arguments")
    if args_node:
        for child in args_node.children:
            if child.type not in ("(", ")", ","):
                text = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                args.append(text[:100])  # Truncate long args
    return args


def build_call_graph(functions: list[FunctionInfo], source: bytes) -> dict[str, set[str]]:
    """Build a call graph between extracted functions."""
    fn_names = {f.name for f in functions}
    # Also match short names (without class prefix)
    short_names = {}
    for f in functions:
        if "." in f.name:
            short = f.name.split(".")[-1]
            short_names[short] = f.name

    graph = {f.name: set() for f in functions}

    for fn in functions:
        calls = _find_identifiers_in_calls(fn.node, source)
        for call_name in calls:
            resolved = call_name
            if call_name in short_names:
                resolved = short_names[call_name]
            if resolved in fn_names and resolved != fn.name:
                graph[fn.name].add(resolved)

    return graph


def _find_identifiers_in_calls(node: Node, source: bytes) -> set[str]:
    """Find all identifiers used in call expressions within a node."""
    names = set()
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn:
            if fn.type == "identifier":
                names.add(source[fn.start_byte:fn.end_byte].decode("utf-8", errors="replace"))
            elif fn.type == "member_expression":
                prop = fn.child_by_field_name("property")
                if prop:
                    names.add(source[prop.start_byte:prop.end_byte].decode("utf-8", errors="replace"))

    for child in node.children:
        names.update(_find_identifiers_in_calls(child, source))
    return names


def find_connected_components(graph: dict[str, set[str]]) -> list[set[str]]:
    """Find connected components in an undirected version of the call graph."""
    # Build undirected adjacency
    adj: dict[str, set[str]] = {k: set(v) for k, v in graph.items()}
    for k, neighbors in graph.items():
        for n in neighbors:
            adj.setdefault(n, set()).add(k)

    visited: set[str] = set()
    components: list[set[str]] = []

    def dfs(node: str, component: set[str]):
        visited.add(node)
        component.add(node)
        for neighbor in adj.get(node, set()):
            if neighbor not in visited:
                dfs(neighbor, component)

    for node in adj:
        if node not in visited:
            component: set[str] = set()
            dfs(node, component)
            components.append(component)

    return components


def chunk_file(file_path: str, max_lines: int = 200) -> list[Chunk]:
    """
    Main chunking function.
    Groups connected functions into semantic chunks.
    Never splits a function in the middle.
    """
    root, source = parse_file(file_path)
    functions = extract_functions(root, source)

    if not functions:
        # Fallback: treat entire file as one chunk
        lines = source.decode("utf-8", errors="replace").split("\n")
        return [Chunk(
            file=file_path,
            line_start=1,
            line_end=len(lines),
            functions=["<module>"],
            content=source.decode("utf-8", errors="replace"),
        )]

    call_graph = build_call_graph(functions, source)
    components = find_connected_components(call_graph)

    fn_map = {f.name: f for f in functions}
    chunks = []

    for component in components:
        group_fns = sorted(
            [fn_map[name] for name in component if name in fn_map],
            key=lambda f: f.start_line,
        )

        if not group_fns:
            continue

        total_lines = group_fns[-1].end_line - group_fns[0].start_line
        if total_lines <= max_lines:
            # Entire group fits in one chunk
            content = "\n\n".join(f.source for f in group_fns)
            crypto = find_crypto_calls(
                parse_source(content.encode("utf-8")),
                content.encode("utf-8"),
                file_path,
            )
            chunks.append(Chunk(
                file=file_path,
                line_start=group_fns[0].start_line,
                line_end=group_fns[-1].end_line,
                functions=[f.name for f in group_fns],
                content=content,
                crypto_calls=[{
                    "method": c.method,
                    "line": group_fns[0].start_line + c.line - 1,
                    "text": c.text,
                } for c in crypto],
            ))
        else:
            # Split at function boundaries
            batch: list[FunctionInfo] = []
            batch_lines = 0
            for fn in group_fns:
                fn_lines = fn.end_line - fn.start_line
                if batch_lines + fn_lines > max_lines and batch:
                    _emit_chunk(chunks, batch, file_path)
                    batch = []
                    batch_lines = 0
                batch.append(fn)
                batch_lines += fn_lines

            if batch:
                _emit_chunk(chunks, batch, file_path)

    # Sort chunks by start line
    chunks.sort(key=lambda c: c.line_start)
    return chunks


def _emit_chunk(chunks: list[Chunk], batch: list[FunctionInfo], file_path: str):
    """Create a Chunk from a batch of functions."""
    content = "\n\n".join(f.source for f in batch)
    crypto = find_crypto_calls(
        parse_source(content.encode("utf-8")),
        content.encode("utf-8"),
        file_path,
    )
    chunks.append(Chunk(
        file=file_path,
        line_start=batch[0].start_line,
        line_end=batch[-1].end_line,
        functions=[f.name for f in batch],
        content=content,
        crypto_calls=[{
            "method": c.method,
            "line": batch[0].start_line + c.line - 1,
            "text": c.text,
        } for c in crypto],
    ))


def get_relevant_imports(root: Node, source: bytes, chunk: Chunk) -> list[str]:
    """Get imports that are referenced in the chunk content."""
    all_imports = extract_imports(root, source)
    relevant = []
    for imp in all_imports:
        # Check if any identifier from the import is used in the chunk
        # Extract imported names
        match = re.search(r'\{([^}]+)\}', imp["text"])
        if match:
            names = [n.strip().split(" as ")[-1].strip() for n in match.group(1).split(",")]
            for name in names:
                if name and name in chunk.content:
                    relevant.append(imp["text"])
                    break
        elif "import " in imp["text"]:
            # Default import
            match = re.search(r'import\s+(\w+)', imp["text"])
            if match and match.group(1) in chunk.content:
                relevant.append(imp["text"])
    return relevant
