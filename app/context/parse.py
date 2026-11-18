"""tree-sitter parsing: function spans for Python / JavaScript / TypeScript (shared by Stage A and C)."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

import tree_sitter_javascript as tsjs
import tree_sitter_python as tspy
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser

PY_FUNC = {"function_definition"}
PY_SCOPE = {"class_definition"}
JS_FUNC = {"function_declaration", "function_expression", "function", "arrow_function", "method_definition",
           "generator_function_declaration", "generator_function"}
JS_SCOPE = {"class_declaration", "class", "abstract_class_declaration"}


@dataclass(frozen=True)
class FunctionSpan:
    name: str          # qualified, e.g. "Cls.method" or "app.get('/x')"
    start: int         # 1-based inclusive
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start + 1


@lru_cache(maxsize=None)
def _language(kind: str) -> Language:
    if kind == "python":
        return Language(tspy.language())
    if kind == "javascript":
        return Language(tsjs.language())
    if kind == "typescript":
        return Language(tsts.language_typescript())
    if kind == "tsx":
        return Language(tsts.language_tsx())
    raise ValueError(kind)


def grammar_for_path(path: str) -> str | None:
    p = path.lower()
    if p.endswith(".py"):
        return "python"
    if p.endswith((".ts", ".mts", ".cts")):
        return "typescript"
    if p.endswith(".tsx"):
        return "tsx"
    if p.endswith((".js", ".jsx", ".mjs", ".cjs")):
        return "javascript"
    return None


def _text(node: Node | None, src: bytes, limit: int = 60) -> str:
    if node is None:
        return ""
    t = src[node.start_byte:node.end_byte].decode("utf-8", "replace")
    t = " ".join(t.split())
    return t if len(t) <= limit else t[:limit] + "…"


def _js_func_name(node: Node, src: bytes) -> str:
    name = node.child_by_field_name("name")
    if name is not None:
        return _text(name, src)
    parent = node.parent
    # const f = () => {} / obj.f = function() {} / {f: () => {}}
    while parent is not None and parent.type in ("parenthesized_expression",):
        parent = parent.parent
    if parent is not None:
        if parent.type == "variable_declarator":
            return _text(parent.child_by_field_name("name"), src)
        if parent.type in ("assignment_expression", "augmented_assignment_expression"):
            return _text(parent.child_by_field_name("left"), src)
        if parent.type in ("pair", "property_assignment"):
            return _text(parent.child_by_field_name("key"), src)
        if parent.type == "public_field_definition":
            return _text(parent.child_by_field_name("name"), src)
        if parent.type == "arguments" and parent.parent is not None and parent.parent.type == "call_expression":
            call = parent.parent
            callee = _text(call.child_by_field_name("function"), src, 40)
            first = parent.named_children[0] if parent.named_children else None
            arg = _text(first, src, 40) if first is not None and first.type in ("string", "template_string") else ""
            return f"{callee}({arg})" if arg else f"{callee}(<callback>)"
    return f"<anonymous@{node.start_point[0] + 1}>"


def functions_in_source(src: bytes, grammar: str) -> list[FunctionSpan]:
    parser = Parser(_language(grammar))
    tree = parser.parse(src)
    is_py = grammar == "python"
    func_types = PY_FUNC if is_py else JS_FUNC
    scope_types = PY_SCOPE if is_py else JS_SCOPE
    out: list[FunctionSpan] = []

    def walk(node: Node, scope: list[str]):
        for child in node.children:
            t = child.type
            if not child.is_named:
                continue  # keyword tokens like `function` / `class` share the node-type names
            if t in func_types:
                if is_py:
                    nm = _text(child.child_by_field_name("name"), src)
                else:
                    nm = _js_func_name(child, src)
                # decorators belong to the function for line matching
                start_node = child.parent if (is_py and child.parent is not None
                                              and child.parent.type == "decorated_definition") else child
                q = ".".join(scope + [nm]) if nm else ".".join(scope)
                out.append(FunctionSpan(q, start_node.start_point[0] + 1, child.end_point[0] + 1))
                walk(child, scope + [nm])
            elif t in scope_types:
                nm = _text(child.child_by_field_name("name"), src) or "<class>"
                walk(child, scope + [nm])
            else:
                walk(child, scope)

    walk(tree.root_node, [])
    return out


def functions_for_file(path: str, src: bytes | str) -> list[FunctionSpan]:
    g = grammar_for_path(path)
    if g is None:
        return []
    if isinstance(src, str):
        src = src.encode("utf-8", "replace")
    try:
        return functions_in_source(src, g)
    except Exception:  # noqa: BLE001 - parser errors should not stop the pipeline
        return []


def enclosing_function(funcs: list[FunctionSpan], start: int, end: int | None = None) -> FunctionSpan | None:
    """Innermost function containing [start, end]; falls back to the one containing `start`."""
    end = start if end is None else end
    containing = [f for f in funcs if f.start <= start and f.end >= end]
    if not containing:
        containing = [f for f in funcs if f.start <= start <= f.end]
    if not containing:
        return None
    return min(containing, key=lambda f: f.length)


def find_by_name(funcs: list[FunctionSpan], name: str | None) -> FunctionSpan | None:
    if not name:
        return None
    same = [f for f in funcs if f.name == name]
    return same[0] if len(same) == 1 else None
