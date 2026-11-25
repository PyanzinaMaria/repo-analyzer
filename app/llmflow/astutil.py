"""Small Python-AST helpers shared by the inventory and stitching (Python-only MVP)."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

AnyFunc = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass
class Param:
    name: str
    pos: int | None          # positional index without self/cls (None = keyword-only / **kwargs)
    kind: str                # positional | kwonly | vararg | kwarg


class SourceCache:
    """Parsed modules of one repository, keyed by repo-relative posix path."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self._trees: dict[str, ast.Module | None] = {}
        self._lines: dict[str, list[str]] = {}
        self._parents: dict[str, dict[int, ast.AST]] = {}

    def text(self, rel: str) -> str:
        try:
            return (self.root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def lines(self, rel: str) -> list[str]:
        if rel not in self._lines:
            self._lines[rel] = self.text(rel).splitlines()
        return self._lines[rel]

    def line(self, rel: str, n: int) -> str:
        ls = self.lines(rel)
        return ls[n - 1].strip() if 0 < n <= len(ls) else ""

    def tree(self, rel: str) -> ast.Module | None:
        if rel not in self._trees:
            try:
                self._trees[rel] = ast.parse(self.text(rel))
            except (SyntaxError, ValueError):
                self._trees[rel] = None
            parents: dict[int, ast.AST] = {}
            if self._trees[rel] is not None:
                for node in ast.walk(self._trees[rel]):
                    for ch in ast.iter_child_nodes(node):
                        parents[id(ch)] = node
            self._parents[rel] = parents
        return self._trees[rel]

    def parent(self, rel: str, node: ast.AST) -> ast.AST | None:
        self.tree(rel)
        return self._parents.get(rel, {}).get(id(node))

    def enclosing(self, rel: str, node: ast.AST, types: tuple) -> ast.AST | None:
        cur = self.parent(rel, node)
        while cur is not None and not isinstance(cur, types):
            cur = self.parent(rel, cur)
        return cur

    def call_at(self, rel: str, line: int, col: int | None = None, name: str | None = None) -> ast.Call | None:
        t = self.tree(rel)
        if t is None:
            return None
        cands = [n for n in ast.walk(t) if isinstance(n, ast.Call) and n.lineno == line]
        if col is not None:
            exact = [c for c in cands if c.col_offset == col - 1]
            if exact:
                # the outermost call starting at that column (`a.b(...)` vs nested `a(...).b(...)`)
                return max(exact, key=lambda c: (c.end_lineno or 0, c.end_col_offset or 0))
        if name:
            named = [c for c in cands if call_name(c) == name]
            if named:
                return named[0]
        return cands[0] if cands else None

    def function_def(self, rel: str, name: str, near_line: int | None = None) -> AnyFunc | None:
        t = self.tree(rel)
        if t is None:
            return None
        defs = [n for n in ast.walk(t) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name]
        if not defs:
            return None
        if near_line is not None:
            inside = [d for d in defs if d.lineno <= near_line <= (d.end_lineno or d.lineno)]
            if inside:
                return min(inside, key=lambda d: (d.end_lineno or d.lineno) - d.lineno)
            return min(defs, key=lambda d: abs(d.lineno - near_line))
        return defs[0]


def call_name(c: ast.Call) -> str | None:
    f = c.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return None


def dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def params(fn: AnyFunc) -> list[Param]:
    a = fn.args
    out: list[Param] = []
    pos_args = list(a.posonlyargs) + list(a.args)
    skip_first = bool(pos_args) and pos_args[0].arg in ("self", "cls")
    idx = 0
    for i, arg in enumerate(pos_args):
        if i == 0 and skip_first:
            continue
        out.append(Param(arg.arg, idx, "positional"))
        idx += 1
    if a.vararg:
        out.append(Param(a.vararg.arg, None, "vararg"))
    for arg in a.kwonlyargs:
        out.append(Param(arg.arg, None, "kwonly"))
    if a.kwarg:
        out.append(Param(a.kwarg.arg, None, "kwarg"))
    return out


def param_defaults(fn: AnyFunc) -> dict[str, ast.AST]:
    a = fn.args
    pos = list(a.posonlyargs) + list(a.args)
    out = {}
    for arg, d in zip(pos[len(pos) - len(a.defaults):], a.defaults):
        out[arg.arg] = d
    for arg, d in zip(a.kwonlyargs, a.kw_defaults):
        if d is not None:
            out[arg.arg] = d
    return out


def clean_param(text: str) -> str:
    """`code: str = "x"` / `*args` → bare parameter name."""
    return text.split(":")[0].split("=")[0].strip().lstrip("*")
