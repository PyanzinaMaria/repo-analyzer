"""Inventory (WP3): LLM call sites → model → declared tools.

Call sites come from the `llmflow.callsite.*` Semgrep rules; the model and the tools are resolved from the
Python AST: literals, module/function constants, parameter defaults, `self.x` assignments, `os.getenv`
defaults, `.env` files and config files of the repository.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from app.context.index import SnapshotIndex
from app.llmflow.astutil import AnyFunc, SourceCache, dotted, param_defaults, params
from app.llmflow.catalog import Catalog
from app.llmflow.kb import match_model
from app.llmflow.models import CallSite, Match, ModelRef, Tool

MAX_DEPTH = 5
CONFIG_GLOBS = ("*.yaml", "*.yml", "*.toml", "*.json", "*.ini", "*.cfg", ".env", ".env.*", "*.env")
CONFIG_SKIP = re.compile(r"(^|/)(node_modules|\.git|\.venv|venv|dist|build|site-packages)/|package(-lock)?\.json$")
MODEL_KEY = re.compile(r"""^\s*["']?([A-Za-z_]*model[A-Za-z_]*)["']?\s*[:=]\s*["']?([A-Za-z0-9][\w./:@-]{1,80})["']?\s*,?\s*$""",
                       re.I | re.M)
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[\"']?([^\"'\n#]*)", re.M)


class RepoConfig:
    """Lazily scanned `.env` and config files (for env var values and `model:` keys)."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self._env: dict[str, tuple[str, str]] | None = None
        self._models: list[tuple[str, str, str]] | None = None

    def _files(self):
        seen = set()
        for g in CONFIG_GLOBS:
            for p in self.root.rglob(g):
                rel = p.relative_to(self.root).as_posix()
                if rel in seen or CONFIG_SKIP.search(rel) or not p.is_file():
                    continue
                try:
                    if p.stat().st_size > 200_000:
                        continue
                except OSError:
                    continue
                seen.add(rel)
                yield rel, p

    def env(self, name: str) -> tuple[str, str] | None:
        if self._env is None:
            self._env = {}
            for rel, p in self._files():
                if ".env" not in p.name:
                    continue
                for k, v in ENV_LINE.findall(p.read_text(encoding="utf-8", errors="replace")):
                    if v.strip():
                        self._env.setdefault(k, (v.strip(), rel))
        return self._env.get(name)

    def model_keys(self) -> list[tuple[str, str, str]]:
        """[(key, value, file)] for lines like `model: gpt-4o` in config files."""
        if self._models is None:
            self._models = []
            for rel, p in self._files():
                for k, v in MODEL_KEY.findall(p.read_text(encoding="utf-8", errors="replace")):
                    if not re.search(r"(?i)(path|dir|file|class|type|provider)$", k) and not v.lower() in (
                            "true", "false", "null", "none"):
                        self._models.append((k, v, rel))
        return self._models

    def model_for_key(self, key: str | None, near: str | None = None) -> tuple[str, str] | None:
        """Value of a `model`-like key from config files that belong to the code at `near`: files in an
        ancestor directory of it, or in a top-level config/conf/settings directory (not another sub-project)."""
        rows = self.model_keys()
        if near is not None:
            src_dir = Path(near).parent.as_posix()

            def related(f: str) -> bool:
                d = Path(f).parent.as_posix()
                top = f.split("/", 1)[0] if "/" in f else ""
                return (d in ("", ".") or src_dir == d or src_dir.startswith(d + "/")
                        or (top in ("config", "configs", "conf", "settings") and d == top))
            rows = [r for r in rows if related(r[2])]
        if key:
            for k, v, f in rows:
                if k.lower() == key.lower():
                    return v, f
        for k, v, f in rows:
            if k.lower() in ("model", "model_name", "llm_model", "chat_model", "default_model"):
                return v, f
        return None


class Resolver:
    def __init__(self, src: SourceCache, cfg: RepoConfig):
        self.src = src
        self.cfg = cfg

    # ---------------------------------------------------------------- model

    def model(self, rel: str, call: ast.Call, arg: str | None, pos: int | None) -> ModelRef:
        self._rel = rel
        expr = None
        if arg:
            expr = next((k.value for k in call.keywords if k.arg == arg), None)
        if expr is None and pos is not None and len(call.args) > pos:
            expr = call.args[pos]
        if expr is None:
            # model passed through **kwargs or not at all: a config-file guess would be arbitrary here
            return ModelRef(None, "unknown", "not passed (**kwargs?)")
        return self.expr(rel, expr, call, 0)

    def expr(self, rel: str, e: ast.AST, ctx: ast.AST, depth: int) -> ModelRef:
        if depth > MAX_DEPTH:
            return ModelRef(None, "unknown", "too deep")
        if isinstance(e, ast.Constant) and isinstance(e.value, str):
            return ModelRef(e.value, "literal" if depth == 0 else "constant")
        if isinstance(e, ast.Name):
            return self._name(rel, e.id, ctx, depth)
        if isinstance(e, ast.Attribute) and isinstance(e.value, ast.Name) and e.value.id in ("self", "cls"):
            return self._self_attr(rel, e.attr, ctx, depth)
        if isinstance(e, ast.Call):
            fn = dotted(e.func) or ""
            if fn in ("os.getenv", "getenv", "os.environ.get", "environ.get"):
                return self._env(rel, e, ctx, depth)
            is_get = isinstance(e.func, ast.Attribute) and e.func.attr == "get"   # also `(cfg or {}).get(...)`
            fn = fn or "….get"
            if is_get and e.args and isinstance(e.args[0], ast.Constant) and isinstance(e.args[0].value, str):
                key = e.args[0].value
                if len(e.args) > 1:
                    inner = self.expr(rel, e.args[1], ctx, depth + 1)
                    if inner.name:
                        return ModelRef(inner.name, "dict-default", f"{fn}({key!r})")
                return self._config_fallback(key, f"{fn}({key!r})")
        if isinstance(e, ast.Subscript):
            base = dotted(e.value) or ""
            key = e.slice.value if isinstance(e.slice, ast.Constant) else None
            if base in ("os.environ", "environ") and isinstance(key, str):
                hit = self.cfg.env(key)
                return ModelRef(hit[0], "env-file", f"{key} in {hit[1]}") if hit else ModelRef(None, "env", key)
            if isinstance(key, str):
                return self._config_fallback(key, f"{base}[{key!r}]")
        if isinstance(e, ast.BoolOp):
            for v in e.values:
                r = self.expr(rel, v, ctx, depth + 1)
                if r.name:
                    return r
        if isinstance(e, ast.IfExp):
            r = self.expr(rel, e.body, ctx, depth + 1)
            return r if r.name else self.expr(rel, e.orelse, ctx, depth + 1)
        if isinstance(e, ast.JoinedStr):
            return ModelRef(None, "unknown", "f-string")
        return ModelRef(None, "unknown", type(e).__name__)

    def _env(self, rel: str, e: ast.Call, ctx: ast.AST, depth: int) -> ModelRef:
        name = e.args[0].value if e.args and isinstance(e.args[0], ast.Constant) else None
        if isinstance(name, str):
            hit = self.cfg.env(name)
            if hit:
                return ModelRef(hit[0], "env-file", f"{name} in {hit[1]}")
        if len(e.args) > 1:
            d = self.expr(rel, e.args[1], ctx, depth + 1)
            if d.name:
                return ModelRef(d.name, "env-default", str(name))
        return ModelRef(None, "env", str(name))

    def _name(self, rel: str, name: str, ctx: ast.AST, depth: int) -> ModelRef:
        fn = self.src.enclosing(rel, ctx, (ast.FunctionDef, ast.AsyncFunctionDef))
        scopes: list[ast.AST] = []
        if fn is not None:
            scopes.append(fn)
        tree = self.src.tree(rel)
        if tree is not None:
            scopes.append(tree)
        line = getattr(ctx, "lineno", 10 ** 9)
        for scope in scopes:
            value = _last_assignment(scope, name, line if scope is fn else None, module=scope is tree)
            if value is not None:
                return self.expr(rel, value, value, depth + 1)
            if scope is fn:
                d = param_defaults(fn).get(name)
                if d is not None:
                    r = self.expr(rel, d, d, depth + 1)
                    if r.name:
                        return ModelRef(r.name, "param-default", f"{fn.name}({name}=…)")
        return self._config_fallback(name, f"name {name}")

    def _self_attr(self, rel: str, attr: str, ctx: ast.AST, depth: int) -> ModelRef:
        cls = self.src.enclosing(rel, ctx, (ast.ClassDef,))
        if cls is not None:
            for node in ast.walk(cls):
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for t in targets:
                        if isinstance(t, ast.Attribute) and t.attr == attr and isinstance(t.value, ast.Name) \
                                and t.value.id == "self" and node.value is not None:
                            r = self.expr(rel, node.value, node.value, depth + 1)
                            if r.name:
                                return r
        return self._config_fallback(attr, f"self.{attr}")

    def _config_fallback(self, key: str | None, detail: str) -> ModelRef:
        hit = self.cfg.model_for_key(key, getattr(self, "_rel", None))
        if hit:
            return ModelRef(hit[0], "config", f"{detail} ~ {hit[1]}")
        return ModelRef(None, "unknown", detail)

    # ---------------------------------------------------------------- tools

    def tools(self, rel: str, call: ast.Call, arg: str | None) -> list[Tool]:
        if not arg:
            return []
        expr = next((k.value for k in call.keywords if k.arg == arg), None)
        if expr is None:
            return []
        dispatch = self._dispatch_dicts(rel)
        out: list[Tool] = []
        for name, fn_name in self._tool_items(rel, expr, call, 0):
            bound = fn_name or dispatch.get(name)
            if bound is None and self.src.function_def(rel, name) is not None:
                bound = name                       # tool named after a function of the same module
            t = Tool(name=name, func_name=bound)
            if bound:
                fdef = self.src.function_def(rel, bound)
                if fdef is not None:
                    t.file, t.line = rel, fdef.lineno
                    t.params = [p.name for p in params(fdef)]
            out.append(t)
        return out

    def _tool_items(self, rel: str, e: ast.AST, ctx: ast.AST, depth: int) -> list[tuple[str, str | None]]:
        if depth > MAX_DEPTH:
            return []
        if isinstance(e, (ast.List, ast.Tuple)):
            out = []
            for el in e.elts:
                out += self._tool_items(rel, el, ctx, depth + 1)
            return out
        if isinstance(e, ast.Dict):
            d = _const_dict(e)
            name = d.get("name")
            fn = d.get("function")
            if isinstance(fn, ast.Dict):
                name = _const_dict(fn).get("name", name)
            return [(name, None)] if isinstance(name, str) else []
        if isinstance(e, ast.Name):
            if self.src.function_def(rel, e.id) is not None:
                return [(e.id, e.id)]               # ollama: tools=[python_function]
            scope = self.src.tree(rel)
            fn = self.src.enclosing(rel, ctx, (ast.FunctionDef, ast.AsyncFunctionDef))
            for s in ([fn] if fn is not None else []) + ([scope] if scope is not None else []):
                v = _last_assignment(s, e.id, None, module=s is scope)
                if v is not None:
                    return self._tool_items(rel, v, v, depth + 1)
        if isinstance(e, ast.Starred):
            return self._tool_items(rel, e.value, ctx, depth + 1)
        return []

    def _dispatch_dicts(self, rel: str) -> dict[str, str]:
        """{"tool_name": "function_name"} from dict literals whose values are functions of this module."""
        tree = self.src.tree(rel)
        out: dict[str, str] = {}
        if tree is None:
            return out
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            pairs = []
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    target = v.id if isinstance(v, ast.Name) else (v.attr if isinstance(v, ast.Attribute) else None)
                    if target and self.src.function_def(rel, target) is not None:
                        pairs.append((k.value, target))
            if pairs and len(pairs) >= max(1, len(node.keys) // 2):
                out.update(dict(pairs))
        return out


def _const_dict(d: ast.Dict) -> dict:
    out = {}
    for k, v in zip(d.keys, d.values):
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            out[k.value] = v.value if isinstance(v, ast.Constant) else v
    return out


def _last_assignment(scope: ast.AST, name: str, before_line: int | None, module: bool) -> ast.AST | None:
    """Value of the last `name = …` in scope (module: top-level statements only)."""
    nodes = scope.body if module else list(ast.walk(scope))
    best = None
    for node in nodes:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        if before_line is not None and node.lineno > before_line:
            continue
        for t in targets:
            if isinstance(t, ast.Name) and t.id == name:
                if best is None or node.lineno >= best[0]:
                    best = (node.lineno, value)
    return best[1] if best else None


def _callee_regex(callee: str) -> re.Pattern:
    parts = [r"[\w.()\[\]]+?" if p.startswith("$") else re.escape(p) for p in callee.split(".")]
    return re.compile("^" + r"\.".join(parts) + "$")


def with_sdk_aliases(cat: Catalog, idx: SnapshotIndex, src: SourceCache) -> tuple[Catalog, list[str]]:
    """Catalog plus call entries for SDK methods bound to a name: `completion = client.chat.completions.create`
    then `completion(model=…, messages=…)` (shell_gpt). Returns (catalog, alias descriptions)."""
    from app.llmflow.catalog import Sdk
    from app.llmflow.rulegen import GENERIC_NAMES

    rxs = [(sdk, call, _callee_regex(call.callee)) for sdk, call in cat.sdk_calls()]
    extra: dict[str, list] = {}
    notes: list[str] = []
    seen: set[str] = set()
    for rel in idx.files:
        tree = src.tree(rel)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.value, ast.Attribute)):
                continue
            t = node.targets[0]
            name = t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else None
            if not name or name in GENERIC_NAMES or name in seen:
                continue
            text = ast.unparse(node.value)
            for sdk, call, rx in rxs:
                if rx.match(text):
                    seen.add(name)
                    alias = call.model_copy(update={
                        "id": f"alias.{call.id}.{name}", "callee": name if isinstance(t, ast.Name) else f"$C.{name}",
                        "inside_import": [], "require_kwargs": [], "exclude": [], "receiver_regex": None,
                        "model_pos": None, "prompt_pos": []})
                    extra.setdefault(sdk.sdk, []).append(alias)
                    notes.append(f"{name} = {text}  ({rel}:{node.lineno})")
                    break
    if not extra:
        return cat, notes
    sdks = list(cat.sdks) + [Sdk(sdk=s.sdk, provider=s.provider, imports=s.imports, calls=extra[s.sdk])
                             for s in cat.sdks if s.sdk in extra]
    return cat.model_copy(update={"sdks": sdks}), notes


def build_inventory(root: Path, cat: Catalog, matches: list[Match], idx: SnapshotIndex,
                    src: SourceCache) -> list[CallSite]:
    order = {c.id: i for i, (_s, c) in enumerate(cat.sdk_calls())}
    best: dict[tuple[str, int], Match] = {}
    for m in matches:
        if m.family != "callsite":
            continue
        key = (m.file, m.line)
        if key not in best or order.get(m.meta.get("call"), 99) < order.get(best[key].meta.get("call"), 99):
            best[key] = m
    res = Resolver(src, RepoConfig(root))
    out: list[CallSite] = []
    for (file, line), m in sorted(best.items()):
        sdk, call = cat.call(m.meta["call"])
        node = src.call_at(file, line, m.col, call.callee.rsplit(".", 1)[-1])
        model = res.model(file, node, call.model_arg, call.model_pos) if node is not None else \
            ModelRef(None, "unknown", "call not parsed")
        if model.name:
            kbm = match_model(cat.kb, model.name)
            model.kb_id = kbm.id if kbm else None
        tools = res.tools(file, node, call.tools_arg) if node is not None else []
        fn = idx.function_at(file, line)
        for t in tools:
            if t.func_name:
                f = next((f for f in idx.all_functions() if f.file == (t.file or file)
                          and f.simple_name == t.func_name), None)
                t.func = f.id if f else None
        out.append(CallSite(id=f"{file}:{line}", file=file, line=line, sdk=sdk.sdk, call=call.id,
                            channel=call.channel, func=fn.id if fn else None, func_name=fn.name if fn else None,
                            model=model, tools=tools))
    return out


def enclosing_def(src: SourceCache, rel: str, line: int) -> AnyFunc | None:
    tree = src.tree(rel)
    if tree is None:
        return None
    best = None
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.lineno <= line <= (n.end_lineno or n.lineno):
            if best is None or n.lineno >= best.lineno:
                best = n
    return best
