"""Per-snapshot code index (spec §5.1): functions, call sites, imports, exports."""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field
from tree_sitter import Node, Parser

from app.core import io
from app.core.yaml_configs import compile_excludes, in_scope
from app.context.parse import _language, enclosing_function, functions_in_source, grammar_for_path

CALL_TYPES = {"call", "call_expression", "new_expression"}
MAX_FILE_BYTES = 1_000_000


class CallSite(BaseModel):
    callee: str        # full callee text, e.g. "subprocess.check_output"
    name: str          # last identifier, e.g. "check_output"
    line: int
    args: str = ""     # truncated argument text (for sink heuristics like shell=True)


class FuncInfo(BaseModel):
    id: str            # "<file>::<qualname>@<start>"
    file: str
    name: str
    start: int
    end: int
    header: str        # decorators + signature (first lines)
    calls: list[CallSite] = Field(default_factory=list)

    @property
    def simple_name(self) -> str:
        return self.name.split(".")[-1]


class FileInfo(BaseModel):
    file: str
    language: str
    loc: int
    imports: list[str] = Field(default_factory=list)
    exports: list[str] = Field(default_factory=list)
    functions: list[FuncInfo] = Field(default_factory=list)
    module_calls: list[CallSite] = Field(default_factory=list)


class SnapshotIndex(BaseModel):
    root: str
    language: str
    files: dict[str, FileInfo] = Field(default_factory=dict)

    def all_functions(self):
        for f in self.files.values():
            yield from f.functions

    def function_at(self, file: str, line: int) -> FuncInfo | None:
        fi = self.files.get(file)
        if not fi:
            return None
        best = None
        for fn in fi.functions:
            if fn.start <= line <= fn.end and (best is None or fn.end - fn.start < best.end - best.start):
                best = fn
        return best


def _text(node: Node | None, src: bytes, limit: int | None = None) -> str:
    if node is None:
        return ""
    t = src[node.start_byte:node.end_byte].decode("utf-8", "replace")
    if limit is not None:
        t = " ".join(t.split())
        if len(t) > limit:
            t = t[:limit] + "…"
    return t


def _last_ident(callee: str) -> str:
    m = re.findall(r"[A-Za-z_$][\w$]*", callee)
    return m[-1] if m else callee


_JS_EXPORT_RES = [
    re.compile(r"module\.exports\.(\w+)\s*="),
    re.compile(r"(?<![\w.])exports\.(\w+)\s*="),
    re.compile(r"export\s+(?:default\s+)?(?:async\s+)?(?:function\*?|class|const|let|var)\s+(\w+)"),
]
_JS_EXPORT_OBJ = re.compile(r"module\.exports\s*=\s*\{([^}]*)\}", re.S)
_JS_EXPORT_LIST = re.compile(r"export\s*\{([^}]*)\}", re.S)
_JS_EXPORT_SINGLE = re.compile(r"module\.exports\s*=\s*(\w+)\s*;?")


def js_exports(text: str) -> list[str]:
    names: list[str] = []
    for rx in _JS_EXPORT_RES:
        names += rx.findall(text)
    for rx in (_JS_EXPORT_OBJ, _JS_EXPORT_LIST):
        for body in rx.findall(text):
            for part in body.split(","):
                part = part.strip()
                if not part:
                    continue
                # "a: b", "a as b", "a"
                m = re.match(r"([\w$]+)\s*(?::\s*([\w$.]+)|\s+as\s+([\w$]+))?", part)
                if m:
                    names.append(m.group(2).split(".")[-1] if m.group(2) else m.group(1))
    names += _JS_EXPORT_SINGLE.findall(text)
    if re.search(r"export\s+default", text):
        names.append("default")
    return sorted(set(names))


def analyze_source(path: str, src: bytes) -> FileInfo | None:
    grammar = grammar_for_path(path)
    if grammar is None:
        return None
    lang = "python" if grammar == "python" else ("typescript" if grammar in ("typescript", "tsx") else "javascript")
    try:
        spans = functions_in_source(src, grammar)
        tree = Parser(_language(grammar)).parse(src)
    except Exception:  # noqa: BLE001
        return None
    lines = src.decode("utf-8", "replace").splitlines()
    fi = FileInfo(file=path, language=lang, loc=sum(1 for ln in lines if ln.strip()))
    funcs: list[FuncInfo] = []
    for sp in spans:
        header_lines = []
        for ln in lines[sp.start - 1: min(sp.end, sp.start + 5)]:
            header_lines.append(ln)
            if ln.rstrip().endswith((":", "{", "=>")) and not ln.lstrip().startswith("@"):
                break
        funcs.append(FuncInfo(id=f"{path}::{sp.name}@{sp.start}", file=path, name=sp.name, start=sp.start,
                              end=sp.end, header="\n".join(header_lines)[:400]))

    def walk(node: Node):
        t = node.type
        if t in CALL_TYPES:
            fn_node = node.child_by_field_name("function") or node.child_by_field_name("constructor")
            callee = _text(fn_node, src, 80)
            args = _text(node.child_by_field_name("arguments"), src, 200)
            line = node.start_point[0] + 1
            cs = CallSite(callee=callee, name=_last_ident(callee), line=line, args=args)
            owner = enclosing_function(spans, line)
            if owner is None:
                fi.module_calls.append(cs)
            else:
                for f in funcs:
                    if f.name == owner.name and f.start == owner.start:
                        f.calls.append(cs)
                        break
            if callee == "require":
                fi.imports.append(_text(node.parent if node.parent is not None else node, src, 160))
        elif t in ("import_statement", "import_from_statement", "future_import_statement"):
            fi.imports.append(_text(node, src, 200))
        for ch in node.children:
            walk(ch)

    walk(tree.root_node)
    fi.functions = funcs
    if lang != "python":
        fi.exports = js_exports(src.decode("utf-8", "replace"))
    fi.imports = list(dict.fromkeys(fi.imports))[:80]
    return fi


def build_index(root: Path, language: str, extensions: list[str], path_excludes: list[str]) -> SnapshotIndex:
    excludes = compile_excludes(path_excludes)
    idx = SnapshotIndex(root=str(root), language=language)
    for p in sorted(root.rglob("*")):
        if not p.is_file() or ".git" in p.parts:
            continue
        rel = p.relative_to(root).as_posix()
        if not in_scope(rel, extensions, excludes):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            src = p.read_bytes()
        except OSError:
            continue
        fi = analyze_source(rel, src)
        if fi is not None:
            idx.files[rel] = fi
    return idx


def load_index(path: Path) -> SnapshotIndex:
    return SnapshotIndex.model_validate(io.read_json(path))
