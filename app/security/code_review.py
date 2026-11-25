from __future__ import annotations

"""Agentic LLM code review → security hypotheses (the promptfoo Code Scanning idea,
generalised from LLM-only risks to any web vulnerability class).

The reviewer gets *tools* (list/read/grep/outline/entrypoints/sinks/callgraph)
and explores the repository itself instead of receiving a fixed dump of files.
It must submit evidence-backed hypotheses with file/line (and, when derivable,
endpoint/parameter), which the dynamic verifier can then "press" with probes.

Without an LLM (or on quota/API errors) a deterministic reviewer runs: it walks
sinks.yaml hits through the call graph from entry points and adds a few
pattern-based checks (hardcoded secrets, dangerous APIs).
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.context.build import build_snapshot_context, load_context
from app.context.callgraph import callees
from app.context.index import FuncInfo, SnapshotIndex
from app.models.finding import Finding, Severity as FindingSeverity
from app.security.config import SecurityConfig, repo_root
from app.security.llm import SecurityLlm, SecurityLlmError
from app.security.models import Severity, Source, VulnClass, VulnHypothesis
from app.security.sast_adapter import cwe_to_vuln_class

logger = logging.getLogger(__name__)

LANGUAGES = {".py": "python", ".js": "javascript", ".ts": "typescript", ".jsx": "javascript",
             ".tsx": "typescript"}

_ROUTE_RE = re.compile(
    r"@\s*[\w.]*\.(route|get|post|put|delete|patch|api_route)\s*\(\s*['\"]([^'\"]+)['\"]"
)
_METHODS_RE = re.compile(r"methods\s*=\s*\[([^\]]+)\]")
_BLUEPRINT_RE = re.compile(
    r"register_blueprint\(\s*(\w+)[^)]*?url_prefix\s*=\s*['\"]([^'\"]+)['\"]"
)
_ROUTER_RE = re.compile(
    r"include_router\(\s*(\w+)[^)]*?prefix\s*=\s*['\"]([^'\"]+)['\"]"
)
_PARAM_RES = (
    re.compile(r"request\.(?:args|form|values|json|data)\.get\(\s*['\"](\w+)"),
    re.compile(r"request\.(?:args|form|values|json)\[\s*['\"](\w+)"),
    re.compile(r"req\.(?:query|body|params)\.(\w+)"),
    re.compile(r"req\.(?:query|body|params)\[\s*['\"](\w+)"),
)

_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|token|private[_-]?key)\b\s*[:=]\s*['\"]([^'\"]{6,})['\"]"
)
_DANGEROUS = (
    (re.compile(r"\beval\s*\("), VulnClass.cmd_injection, "eval() исполняет строку как код"),
    (re.compile(r"\bexec\s*\("), VulnClass.cmd_injection, "exec() исполняет строку как код"),
    (re.compile(r"os\.system\s*\("), VulnClass.cmd_injection, "os.system() с внешними данными"),
    (re.compile(r"subprocess\.[\w_]+\([^)]*shell\s*=\s*True"), VulnClass.cmd_injection,
     "subprocess с shell=True"),
    (re.compile(r"pickle\.loads?\s*\("), VulnClass.insecure_deserialization, "pickle.load(s)"),
    (re.compile(r"yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)"),
     VulnClass.insecure_deserialization, "yaml.load без SafeLoader"),
    (re.compile(r"render_template_string\s*\("), VulnClass.xss, "render_template_string с данными"),
    (re.compile(r"innerHTML\s*="), VulnClass.xss, "innerHTML с внешними данными"),
    (re.compile(r"document\.write\s*\("), VulnClass.xss, "document.write с внешними данными"),
    (re.compile(r"Markup\s*\(|mark_safe\s*\("), VulnClass.xss, "неэкранированный HTML"),
    (re.compile(r"requests\.(?:get|post)\([^)]*verify\s*=\s*False"), VulnClass.ssrf,
     "TLS-проверка отключена при внешнем запросе"),
)


@dataclass
class CodeContext:
    root: Path
    language: str
    index: SnapshotIndex
    entrypoints: dict[str, str]
    sinks: list[dict[str, Any]]
    graph: Any
    ctx_dir: Path
    blueprints: dict[str, str] = field(default_factory=dict)
    _code_cache: dict[str, list[str]] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------- helpers
    def files(self) -> list[str]:
        return sorted(self.index.files)

    def lines(self, rel: str) -> list[str]:
        if rel not in self._code_cache:
            path = self.root / rel
            try:
                self._code_cache[rel] = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._code_cache[rel] = []
        return self._code_cache[rel]

    def read(self, rel: str, start: int = 1, end: int | None = None) -> str:
        lines = self.lines(rel)
        if not lines:
            return ""
        start = max(1, start)
        end = min(len(lines), end or start + 80)
        return "\n".join(f"{i:4d}| {lines[i - 1]}" for i in range(start, min(end, len(lines)) + 1))

    def function_at(self, rel: str, line: int) -> FuncInfo | None:
        return self.index.function_at(rel, line)

    def functions(self) -> list[FuncInfo]:
        return list(self.index.all_functions())

    def params_of(self, fn: FuncInfo) -> list[str]:
        body = self.read(fn.file, fn.start, fn.end)
        found: list[tuple[int, str]] = []
        for rx in _PARAM_RES:
            found.extend((m.start(), m.group(1)) for m in rx.finditer(body))
        found.sort()
        seen: list[str] = []
        for _, name in found:
            if name not in seen:
                seen.append(name)
        return seen[:6]

    def route_of(self, fn: FuncInfo) -> tuple[str | None, str, list[str]]:
        """(path, method, params) from a route decorator and request.* usage.

        Flask blueprints / FastAPI routers are resolved to their mounted prefix
        (``@mod_user.route('/login')`` + ``url_prefix='/user'`` -> ``/user/login``).
        """
        header = fn.header or ""
        m = _ROUTE_RE.search(header)
        if not m:
            return None, "GET", self.params_of(fn)
        decorator, path = m.group(1), m.group(2)
        prefix = self.blueprints.get(Path(fn.file).stem)
        if prefix:
            path = prefix.rstrip("/") + "/" + path.lstrip("/")
        method = "GET"
        if decorator.upper() in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
            method = decorator.upper()
        methods = _METHODS_RE.search(header)
        if methods and "POST" in methods.group(1).upper():
            method = "POST"
        return path, method, self.params_of(fn)

    def entrypoint_rows(self) -> list[dict[str, Any]]:
        rows = []
        by_id = {fn.id: fn for fn in self.functions()}
        for fn_id, reason in self.entrypoints.items():
            fn = by_id.get(fn_id)
            if fn is None:
                continue
            path, method, params = self.route_of(fn)
            rows.append({"id": fn_id, "file": fn.file, "function": fn.simple_name,
                         "line": fn.start, "reason": reason, "path": path,
                         "method": method, "params": params})
        return rows

    # tools exposed to the model ------------------------------------------
    def tool_list_files(self, pattern: str = "") -> list[str]:
        files = self.files()
        if pattern:
            rx = re.compile(pattern, re.I)
            files = [f for f in files if rx.search(f)]
        return files[:200]

    def tool_outline(self, rel: str) -> list[str]:
        fi = self.index.files.get(rel)
        if not fi:
            return []
        return [f"{fn.start:5d}-{fn.end:<5d} {fn.simple_name}  ({fn.header.splitlines()[0][:120]})"
                for fn in fi.functions]

    def tool_grep(self, pattern: str, limit: int = 40) -> list[dict[str, Any]]:
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            return [{"error": f"bad regex: {exc}"}]
        hits: list[dict[str, Any]] = []
        for rel in self.files():
            for i, line in enumerate(self.lines(rel), 1):
                if rx.search(line):
                    hits.append({"file": rel, "line": i, "text": line.strip()[:200]})
                    if len(hits) >= limit:
                        return hits
        return hits

    def tool_callgraph(self, function: str) -> dict[str, list[dict[str, Any]]]:
        rows = callees(self.graph, function)
        return {"callees": [{"id": fid, "depth": depth} for fid, depth in rows[:30]]}


def detect_language(root: Path) -> str:
    counts: dict[str, int] = {}
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in LANGUAGES and ".venv" not in path.parts:
            lang = LANGUAGES[path.suffix]
            counts[lang] = counts.get(lang, 0) + 1
    if not counts:
        return "python"
    return max(counts, key=counts.get)


def discover_blueprints(root: Path) -> dict[str, str]:
    """Map module stem -> mounted prefix (Flask blueprints / FastAPI routers)."""
    out: dict[str, str] = {}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in LANGUAGES:
            continue
        if any(part in {".venv", "venv", "node_modules", "__pycache__"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for rx in (_BLUEPRINT_RE, _ROUTER_RE):
            for match in rx.finditer(text):
                out.setdefault(match.group(1), match.group(2))
    return out


def build_code_context(root: Path, language: str | None = None,
                       cfg: SecurityConfig | None = None) -> CodeContext:
    root = root.resolve()
    language = language or detect_language(root)
    digest = hashlib.sha1(f"{root}:{language}".encode()).hexdigest()[:12]
    ctx_dir = repo_root() / "data" / "context" / digest
    ctx_dir.mkdir(parents=True, exist_ok=True)
    build_snapshot_context(root, language, ctx_dir, force=False)
    snap = load_context(root, ctx_dir)
    import json as _json
    sinks = _json.loads((ctx_dir / "sinks.json").read_text(encoding="utf-8"))
    return CodeContext(root=root, language=language, index=snap.idx,
                       entrypoints=snap.entrypoints, sinks=sinks, graph=snap.graph,
                       ctx_dir=ctx_dir, blueprints=discover_blueprints(root))


# ------------------------------------------------------------- deterministic
def _entry_ancestors(graph: Any, fn_id: str, entry_ids: set[str], depth: int = 4) -> list[tuple[str, int]]:
    """Entry points that (transitively) call `fn_id`, with the hop distance."""
    try:
        reverse = graph.reverse(copy=False)
    except Exception:  # noqa: BLE001
        return []
    frontier = {fn_id}
    seen = {fn_id}
    found: list[tuple[str, int]] = []
    for distance in range(1, depth + 1):
        nxt: set[str] = set()
        for node in frontier:
            try:
                nxt.update(reverse.neighbors(node))
            except Exception:  # noqa: BLE001
                continue
        nxt -= seen
        found.extend((n, distance) for n in nxt if n in entry_ids)
        seen |= nxt
        frontier = nxt
        if not frontier:
            break
    return found


def _reachable_from_entry(graph: Any, fn_id: str, depth: int = 2) -> bool:
    """Is `fn_id` called (directly or transitively) from any entry point?"""
    try:
        reverse = graph.reverse(copy=False)
    except Exception:  # noqa: BLE001
        return False
    frontier = {fn_id}
    seen = {fn_id}
    for _ in range(depth):
        nxt: set[str] = set()
        for node in frontier:
            try:
                nxt.update(reverse.neighbors(node))
            except Exception:  # noqa: BLE001
                continue
        nxt -= seen
        if not nxt:
            break
        seen |= nxt
        frontier = nxt
    return len(seen) > 1


_DEF_RE = re.compile(r"def\s+\w+\s*\(([^)]*)\)")
_TAINT_REQUIRED = {VulnClass.open_redirect, VulnClass.path_traversal, VulnClass.ssrf,
                   VulnClass.cmd_injection, VulnClass.sqli,
                   VulnClass.insecure_deserialization, VulnClass.xxe}


def _function_params(fn: FuncInfo) -> list[str]:
    m = _DEF_RE.search(fn.header or "")
    if not m:
        return []
    names = []
    for chunk in m.group(1).split(","):
        name = chunk.strip().split(":")[0].split("=")[0].strip().lstrip("*")
        if name and name not in {"self", "cls"} and name.isidentifier():
            names.append(name)
    return names


def _passed_request_data(fn: FuncInfo, ctx: "CodeContext") -> bool:
    """Is this function called from an entry point with one of its request params?"""
    by_id = {f.id: f for f in ctx.functions()}
    for entry_id in ctx.entrypoints:
        entry = by_id.get(entry_id)
        if entry is None or entry.id == fn.id:
            continue
        params = ctx.params_of(entry)
        if not params:
            continue
        for line in ctx.lines(entry.file)[entry.start - 1:entry.end]:
            if f"{fn.simple_name}(" not in line:
                continue
            if any(re.search(rf"\b{re.escape(p)}\w*", line) for p in params):
                return True
    return False


def _tainted(sink_line: int, fn: FuncInfo, ctx: "CodeContext", callee: str | None = None) -> bool:
    """Heuristic dataflow: do the sink arguments use a request value?

    Direct: the call arguments mention a ``request.*`` parameter of the function.
    Local: an identifier in the arguments is assigned from a request value a few
    lines above (``filepath = os.path.join(..., filename)``).
    One hop: the function is called by an entry point with its request parameter.
    A constant ``redirect('/')`` therefore does not count, while
    ``db.find_user(username)`` from a login route does.
    """
    req = set(ctx.params_of(fn))
    call = next((c for c in fn.calls
                 if c.line == sink_line and (callee is None or c.callee == callee)), None)
    if call is None:
        # nested callee text can share a line and carry empty args; take one with args
        call = next((c for c in fn.calls
                     if c.line == sink_line and c.args and c.args.strip() not in {"", "()"}), None)
    args = (call.args if call is not None else "") or ""
    if not args:
        return False
    if req and any(re.search(rf"\b{re.escape(n)}\w*", args) for n in req):
        return True
    # follow one local assignment: sink(filepath) <- filepath = join(..., filename)
    for ident in set(re.findall(r"\b[A-Za-z_]\w*\b", args)):
        for line_no in range(sink_line - 1, fn.start - 1, -1):
            text = ctx.lines(fn.file)[line_no - 1]
            if re.match(rf"\s*{re.escape(ident)}\s*=", text):
                if req and any(re.search(rf"\b{re.escape(p)}\w*", text) for p in req):
                    return True
                break
    return _passed_request_data(fn, ctx)


def _caller_routes(fn: FuncInfo, ctx: "CodeContext") -> list[tuple[str, str, str | None]]:
    """Routes that call `fn`, with the request parameter passed at the call site."""
    by_id = {f.id: f for f in ctx.functions()}
    out: list[tuple[str, str, str | None]] = []
    for entry_id in ctx.entrypoints:
        entry = by_id.get(entry_id)
        if entry is None or entry.id == fn.id:
            continue
        path, method, params = ctx.route_of(entry)
        if not path:
            continue
        for line in ctx.lines(entry.file)[entry.start - 1:entry.end]:
            if f"{fn.simple_name}(" not in line:
                continue
            passed = next((p for p in params
                           if re.search(rf"\b{re.escape(p)}\w*", line)), None)
            out.append((path, method, passed or (params[0] if params else None)))
            break
    return out


def _sink_targets(fn: FuncInfo, ctx: "CodeContext", entry_ids: set[str]) -> tuple[list[tuple[str | None, str, str | None, list[str]]], float, str]:
    """(endpoint, method, param, all_params) targets, plus confidence and reason."""
    if fn.id in entry_ids:
        path, method, params = ctx.route_of(fn)
        return [(path, method, params[0] if params else None, params)], 0.7, "опасный вызов в функции-точке входа"
    by_id = {f.id: f for f in ctx.functions()}
    routes: list[tuple[str | None, str, str | None, list[str]]] = []
    for entry_id in ctx.entrypoints:
        entry = by_id.get(entry_id)
        if entry is None or entry.id == fn.id:
            continue
        path, method, params = ctx.route_of(entry)
        if not path:
            continue
        for line in ctx.lines(entry.file)[entry.start - 1:entry.end]:
            if f"{fn.simple_name}(" not in line:
                continue
            passed = next((p for p in params
                           if re.search(rf"\b{re.escape(p)}\w*", line)), None)
            routes.append((path, method, passed or (params[0] if params else None), params))
            break
    if routes:
        return routes, 0.65, "опасный вызов достижим из точки входа"
    return [(None, "GET", None, [])], 0.35, "опасный вызов в функции без явной точки входа"


def deterministic_hypotheses(ctx: CodeContext, cfg: SecurityConfig) -> list[VulnHypothesis]:
    """Rule-based reviewer: sink hits reachable from entry points + patterns."""
    out: list[VulnHypothesis] = []
    by_id = {fn.id: fn for fn in ctx.functions()}
    entry_ids = set(ctx.entrypoints)
    entry_rows = {row["id"]: row for row in ctx.entrypoint_rows()}

    for sink in ctx.sinks:
        vuln_class = cwe_to_vuln_class(sink.get("cwe"))
        if vuln_class is None:
            continue
        fn = by_id.get(sink.get("function_id") or "")
        if fn is None:
            continue
        # a dangerous callee with constant arguments is not a vulnerability:
        # require a value from the request / function parameters near the sink.
        if vuln_class in _TAINT_REQUIRED and not _tainted(
                int(sink["line"]), fn, ctx, callee=sink.get("callee")):
            continue
        targets, confidence, why = _sink_targets(fn, ctx, entry_ids)
        for path, method, param, params in targets:
            out.append(VulnHypothesis(
                vuln_class=vuln_class, source=Source.sast,
                title=f"{vuln_class.value} в {fn.file}:{sink['line']}",
                description=f"{why}: {sink.get('callee')}",
                confidence=confidence, severity=Severity.high,
                file=fn.file, line=int(sink["line"]), function=fn.simple_name,
                endpoint=path, method=method, param=param,
                evidence=f"вызов {sink.get('callee')} ({why})",
                meta={"reviewer": "deterministic", "sink_cwe": sink.get("cwe"),
                      "params": list(params)},
            ))

    # hardcoded secrets and dangerous APIs
    covered = {(h.file, h.line) for h in out}
    for rel in ctx.files():
        for i, line in enumerate(ctx.lines(rel), 1):
            if (rel, i) in covered:
                continue
            if _SECRET_RE.search(line) and "example" not in line.lower():
                out.append(VulnHypothesis(
                    vuln_class=VulnClass.hardcoded_secret, source=Source.llm_review,
                    title=f"Возможный секрет в коде: {rel}:{i}",
                    description="Строка похожа на пароль/токен/ключ, зашитый в код.",
                    confidence=0.55, severity=Severity.medium, file=rel, line=i,
                    evidence=line.strip()[:200],
                    meta={"reviewer": "deterministic", "pattern": "secret"},
                ))
                covered.add((rel, i))
                continue
            for rx, vuln_class, why in _DANGEROUS:
                if rx.search(line):
                    out.append(VulnHypothesis(
                        vuln_class=vuln_class, source=Source.llm_review,
                        title=f"{vuln_class.value}: {rel}:{i}",
                        description=why, confidence=0.45, severity=Severity.medium,
                        file=rel, line=i, evidence=line.strip()[:200],
                        meta={"reviewer": "deterministic", "pattern": why},
                    ))
                    covered.add((rel, i))
                    break
    return out


# --------------------------------------------------------------------- LLM
_SYSTEM = """Ты — старший AppSec-инженер, который ищет уязвимости в исходном коде.
Твоя задача — НЕ пересказать код, а найти конкретные подозрительные места и
сформулировать гипотезы, которые можно проверить динамически (запросами к приложению).

Ищи уязвимости любых классов, а не только LLM-риски: SQL-инъекции, XSS, path traversal,
SSRF, XXE, инъекции команд, open redirect, небезопасная десериализация, секреты в коде,
отсутствие проверок доступа.

Правила:
- каждая гипотеза должна опираться на конкретный файл и строку (или функцию);
- если можешь, укажи эндпоинт и параметр, через который входные данные доходят до опасной операции;
- не выдумывай файлы, строки и CVE; сомнительные гипотезы помечай низкой уверенностью;
- используй инструменты, чтобы проверить путь данных, а не гадай;
- если нашёл хотя бы одно подозрительное место — ОБЯЗАТЕЛЬНО вызови submit с гипотезами;
  finish — только если действительно ничего не нашёл.

Инструменты (используй function calling; если он недоступен — верни JSON с полем action и args):
- list_files({"pattern": "<regex>"}) — список файлов
- outline({"file": "<path>"}) — функции файла с диапазонами строк
- read_file({"file": "<path>", "start": 1, "end": 120}) — код с номерами строк
- grep({"pattern": "<regex>"}) — поиск по репозиторию
- entrypoints({}) — точки входа и их маршруты
- sinks({}) — опасные вызовы, найденные каталогом sinks.yaml
- callgraph({"function": "<name>"}) — что вызывает функция
- submit({"hypotheses": [...]}) — завершить и отдать гипотезы
- finish({"reason": "..."}) — завершить без новых гипотез

Формат гипотезы:
{"vuln_class": "sqli|xss|path_traversal|open_redirect|cmd_injection|xxe|ssrf|insecure_deserialization|hardcoded_secret|prompt_injection",
 "file": "rel/path.py", "line": 42, "function": "name", "endpoint": "/route", "method": "GET",
 "param": "q", "confidence": 0.0-1.0, "severity": "critical|high|medium|low",
 "title": "...", "description": "почему это уязвимо и как данные доходят"}

Отвечай ТОЛЬКО JSON-объектом: {"action": "...", "args": {...}, "thought": "..."}
Если доступен function calling — вызывай функции напрямую, без текстовых пояснений.
"""


def _briefing(ctx: CodeContext, cfg: SecurityConfig) -> str:
    eps = ctx.entrypoint_rows()
    top_eps = eps[:12]
    sink_lines = []
    by_cwe: dict[str, int] = {}
    for s in ctx.sinks:
        by_cwe[s.get("cwe", "?")] = by_cwe.get(s.get("cwe", "?"), 0) + 1
    for s in ctx.sinks[:15]:
        sink_lines.append(f"- {s.get('file')}:{s.get('line')} {s.get('callee')} ({s.get('cwe')})")
    lines = [
        f"Репозиторий: {ctx.root.name} (язык: {ctx.language})",
        f"Файлов: {len(ctx.index.files)}, функций: {len(ctx.functions())}, "
        f"точек входа: {len(eps)}, опасных вызовов: {len(ctx.sinks)}",
        "Распределение стоков по CWE: " + ", ".join(f"{k}:{v}" for k, v in sorted(by_cwe.items())),
        "",
        "Точки входа (файл:строка, функция, маршрут, параметры):",
    ]
    for e in top_eps:
        lines.append(f"- {e['file']}:{e['line']} {e['function']} -> {e['method']} {e['path']} "
                     f"params={e['params']}")
    lines += ["", "Опасные вызовы (первые 15):", *sink_lines]
    lines += ["", "Файлы и функции (строка начала):"]
    for rel in sorted(ctx.index.files)[:6]:
        fi = ctx.index.files.get(rel)
        if fi is None:
            continue
        fns = ", ".join(f"{fn.simple_name}:{fn.start}" for fn in fi.functions[:8])
        lines.append(f"- {rel} ({fi.loc} строк): {fns}")
    if cfg.review_guidance:
        lines += ["", "Дополнительные требования заказчика:", cfg.review_guidance]
    lines += ["", "Исследуй код инструментами и верни submit с гипотезами."]
    return "\n".join(lines)


def _execute_tool(ctx: CodeContext, action: str, args: dict[str, Any]) -> Any:
    if action == "list_files":
        return ctx.tool_list_files(str(args.get("pattern") or ""))
    if action == "outline":
        return ctx.tool_outline(str(args.get("file") or ""))
    if action == "read_file":
        return ctx.read(str(args.get("file") or ""), int(args.get("start") or 1),
                        int(args.get("end") or 120))
    if action == "grep":
        return ctx.tool_grep(str(args.get("pattern") or ""))
    if action == "entrypoints":
        return ctx.entrypoint_rows()[:20]
    if action == "sinks":
        return ctx.sinks[:40]
    if action == "callgraph":
        return ctx.tool_callgraph(str(args.get("function") or ""))
    return {"error": f"unknown tool: {action}"}


def _normalize_hypotheses(raw: Any, ctx: CodeContext) -> list[VulnHypothesis]:
    if not isinstance(raw, list):
        return []
    out: list[VulnHypothesis] = []
    for item in raw[:60]:
        if not isinstance(item, dict):
            continue
        try:
            vuln_class = VulnClass(str(item.get("vuln_class") or "").strip())
        except ValueError:
            continue
        rel = str(item.get("file") or "").strip()
        if rel not in ctx.index.files:
            continue
        line = item.get("line")
        line = int(line) if str(line).isdigit() else None
        try:
            confidence = max(0.0, min(1.0, float(item.get("confidence", 0.5))))
        except (TypeError, ValueError):
            confidence = 0.5
        try:
            severity = Severity(str(item.get("severity") or "medium").lower())
        except ValueError:
            severity = Severity.medium
        fn = ctx.function_at(rel, line or 0)
        evidence = ""
        if line:
            evidence = "\n".join(ctx.lines(rel)[max(0, line - 2):line + 1])[:300]
        out.append(VulnHypothesis(
            vuln_class=vuln_class, source=Source.llm_review,
            title=str(item.get("title") or f"{vuln_class.value} в {rel}:{line or '?'}"),
            description=str(item.get("description") or ""),
            confidence=confidence, severity=severity, file=rel, line=line,
            function=str(item.get("function") or (fn.simple_name if fn else "")) or None,
            endpoint=item.get("endpoint"), method=item.get("method"),
            param=item.get("param"), evidence=evidence or str(item.get("description") or ""),
            meta={"reviewer": "llm"},
        ))
    return out


def _openai_tools() -> list[dict[str, Any]]:
    """Native function-calling schemas (Groq/OpenAI-compatible models require
    tools to be declared, otherwise a model that decides to call one gets 400)."""
    def fn(name: str, description: str, properties: dict[str, Any],
           required: list[str] | None = None) -> dict[str, Any]:
        return {"type": "function", "function": {
            "name": name, "description": description,
            "parameters": {"type": "object", "properties": properties,
                           "required": required or []},
        }}

    hypothesis_item = {
        "type": "object",
        "properties": {
            "vuln_class": {"type": "string", "enum": [v.value for v in VulnClass]},
            "file": {"type": "string"},
            "line": {"type": "integer"},
            "function": {"type": "string"},
            "endpoint": {"type": "string"},
            "method": {"type": "string"},
            "param": {"type": "string"},
            "confidence": {"type": "number"},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
            "title": {"type": "string"},
            "description": {"type": "string"},
        },
        "required": ["vuln_class", "file", "confidence", "title"],
    }
    return [
        fn("list_files", "Список файлов репозитория (regex-фильтр).",
           {"pattern": {"type": "string"}}),
        fn("outline", "Функции файла с диапазонами строк.",
           {"file": {"type": "string"}}, ["file"]),
        fn("read_file", "Прочитать файл с номерами строк.",
           {"file": {"type": "string"}, "start": {"type": "integer"},
            "end": {"type": "integer"}}, ["file"]),
        fn("grep", "Поиск по регулярному выражению во всех файлах.",
           {"pattern": {"type": "string"}}, ["pattern"]),
        fn("entrypoints", "Точки входа (маршруты, параметры).", {}),
        fn("sinks", "Опасные вызовы из каталога sinks.yaml.", {}),
        fn("callgraph", "Что вызывает функция (по имени).",
           {"function": {"type": "string"}}, ["function"]),
        fn("submit", "Завершить и вернуть гипотезы уязвимостей.",
           {"hypotheses": {"type": "array", "items": hypothesis_item}},
           ["hypotheses"]),
        fn("finish", "Завершить без новых гипотез.", {"reason": {"type": "string"}}),
    ]


def _compact_messages(messages: list[dict[str, Any]], budget_chars: int = 12000) -> list[dict[str, Any]]:
    """Keep the free Groq TPM budget (8k tokens/min) from overflowing.

    Tool-call pairs (assistant.tool_calls + tool result) must stay together,
    otherwise the API rejects the conversation. We keep the last three groups,
    truncate old results, and leave the latest result large enough to be useful.
    """
    if len(messages) <= 2:
        return messages
    head = [messages[0], {"role": "user", "content": messages[1]["content"][:5000]}]
    tail = messages[2:]
    groups: list[list[dict[str, Any]]] = []
    i = len(tail) - 1
    while i >= 0 and len(groups) < 3:
        message = tail[i]
        if message.get("role") == "tool":
            j = i - 1
            while j >= 0 and tail[j].get("role") != "assistant":
                j -= 1
            if j >= 0:
                groups.append([tail[j], message])
                i = j - 1
                continue
        groups.append([message])
        i -= 1
    groups.reverse()

    out: list[dict[str, Any]] = list(head)
    flat: list[dict[str, Any]] = [m for group in groups for m in group]
    for index, message in enumerate(flat):
        content = message.get("content") or ""
        limit = 4000 if message.get("role") == "tool" and index == len(flat) - 1 else 800
        item: dict[str, Any] = {"role": message["role"], "content": content[:limit]}
        if message.get("tool_calls"):
            item["tool_calls"] = message["tool_calls"]
        if message.get("tool_call_id"):
            item["tool_call_id"] = message["tool_call_id"]
        out.append(item)
    while sum(len(m.get("content") or "") for m in out) > budget_chars and len(out) > 2:
        out.pop(2)
    return out


def llm_hypotheses(ctx: CodeContext, cfg: SecurityConfig, llm: SecurityLlm) -> list[VulnHypothesis]:
    """Agentic review loop.

    A malformed model answer is retried by the LLM client itself; if a step still
    fails after retries, we keep whatever hypotheses were already submitted (or
    raise on the very first step so the caller can fall back to the deterministic
    reviewer). Each step has a bounded observation size to control tokens.
    """
    messages = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": _briefing(ctx, cfg)},
    ]
    nudged_finish = False
    nudged_submit = False
    total_steps = max(1, cfg.review_max_steps)
    all_tools = _openai_tools()
    submit_tools = [t for t in all_tools
                    if t["function"]["name"] in {"submit", "finish"}]
    for step in range(total_steps):
        remaining = total_steps - step
        if remaining <= 3:
            # near the budget: only submit/finish remain, otherwise the model
            # keeps reading the same file until the step limit
            tools_for_step = submit_tools
            if not nudged_submit:
                nudged_submit = True
                messages.append({"role": "user", "content":
                                 "Осталось мало шагов и ты уже видел ключевые файлы. "
                                 "Вызови submit с гипотезами, которые подтверждаются кодом, "
                                 "или finish, если их нет."})
        else:
            tools_for_step = all_tools
        try:
            answer = llm.chat_json(_compact_messages(messages), max_tokens=1200,
                                   tools=tools_for_step)
        except SecurityLlmError as exc:
            if step == 0:
                raise
            logger.warning("LLM review stopped at step %s: %s", step, exc)
            return _final_submit(ctx, llm, messages)
        action = str(answer.get("action") or "")
        args = answer.get("args") or {}
        thought = str(answer.get("thought") or "")
        logger.info("llm review step %s: action=%s args=%s", step, action,
                    json.dumps(args, ensure_ascii=False)[:400])
        if action == "submit":
            hypotheses = _normalize_hypotheses(args.get("hypotheses") or [], ctx)
            if hypotheses:
                return hypotheses
            if step < cfg.review_max_steps - 1:
                messages.append({"role": "user", "content":
                                 "В submit не было валидных гипотез. Проверь код инструментами "
                                 "и отправь хотя бы одну гипотезу с file/line, либо вызови finish."})
                continue
            return []
        if action == "finish":
            if not nudged_finish and step < cfg.review_max_steps - 1:
                nudged_finish = True
                messages.append({"role": "user", "content":
                                 "Перед завершением: если есть хоть одно подозрительное место — "
                                 "вызови submit с гипотезами; finish — только если совсем ничего нет."})
                continue
            return []
        if not action:
            # a valid JSON object without a tool: nudge instead of crashing
            messages.append({"role": "assistant",
                             "content": json.dumps(answer, ensure_ascii=False)[:600]})
            messages.append({"role": "user", "content":
                             "Не указан action. Верни JSON вида "
                             '{"action": "read_file|grep|submit|finish", "args": {...}}.'})
            continue
        observation = _execute_tool(ctx, action, args)
        obs_text = json.dumps(observation, ensure_ascii=False)
        tool_call = answer.get("_tool_call")
        if tool_call:
            call = {key: tool_call.get(key) for key in ("id", "type", "function")}
            messages.append({"role": "assistant", "content": None, "tool_calls": [call]})
            messages.append({"role": "tool", "tool_call_id": call.get("id") or "",
                             "content": obs_text[:4000]})
        else:
            obs_limit = 5000 if action in {"read_file", "outline", "entrypoints", "sinks"} else 1200
            messages.append({"role": "assistant", "content": json.dumps(
                {"action": action, "args": args, "thought": thought},
                ensure_ascii=False)[:600]})
            messages.append({"role": "user", "content": "Наблюдение:\n" +
                              obs_text[:obs_limit] + "\n\nСледующий шаг?"})
    return _final_submit(ctx, llm, messages)


def _final_submit(ctx: CodeContext, llm: SecurityLlm,
                  messages: list[dict[str, str]]) -> list[VulnHypothesis]:
    """One last forced attempt: by now the model has seen the code, make it submit."""
    submit_only = [t for t in _openai_tools() if t["function"]["name"] == "submit"]
    try:
        answer = llm.chat_json(
            _compact_messages(messages + [{"role": "user", "content":
                "Шаги закончились. Вызови submit СЕЙЧАС с гипотезами, которые уже подтвердил кодом. "
                "Если совсем ничего нет — finish."}]),
            max_tokens=1500, tools=submit_only,
        )
    except SecurityLlmError as exc:
        logger.warning("final submit failed: %s", exc)
        return []
    if str(answer.get("action") or "") == "submit":
        return _normalize_hypotheses((answer.get("args") or {}).get("hypotheses") or [], ctx)
    logger.info("final submit returned action=%s", answer.get("action"))
    return []


_DIRECT_SYSTEM = """Ты — старший AppSec-инженер. Тебе дают обзор репозитория и
фрагменты кода-кандидатов, найденные по опасным вызовам. Найди уязвимости,
которые действительно подтверждаются кодом.

Верни ТОЛЬКО JSON:
{"hypotheses": [{
  "vuln_class": "sqli|xss|path_traversal|open_redirect|cmd_injection|xxe|ssrf|insecure_deserialization|hardcoded_secret|prompt_injection",
  "file": "rel/path.py", "line": 42, "function": "name",
  "endpoint": "/route", "method": "GET|POST", "param": "q",
  "confidence": 0.0, "severity": "critical|high|medium|low",
  "title": "...", "description": "как пользовательские данные доходят до опасной операции"
}]}

Правила:
- не выдумывай файлы, строки и CVE;
- если фрагмент не уязвим (константы, нет пользовательского ввода) — не включай его;
- сомнительные места помечай confidence <= 0.4;
- максимум 10 гипотез.
"""


def _direct_prompt(ctx: CodeContext, cfg: SecurityConfig,
                   candidates: list[VulnHypothesis]) -> str:
    lines = [_briefing(ctx, cfg)[:4000], "", "Фрагменты кода кандидатов:"]
    seen: set[tuple[str, str | None]] = set()
    shown = 0
    for hypothesis in candidates:
        if not hypothesis.file or not hypothesis.line:
            continue
        key = (hypothesis.vuln_class.value, hypothesis.file)
        if key in seen:
            continue
        seen.add(key)
        start = max(1, hypothesis.line - 8)
        end = hypothesis.line + 14
        code = ctx.read(hypothesis.file, start, end)
        lines.append(f"\n### {hypothesis.file}:{hypothesis.line} "
                     f"({hypothesis.vuln_class.value}, {hypothesis.cwe}) — {hypothesis.description[:160]}")
        lines.append(code[:1600])
        shown += 1
        if shown >= 5:
            break
    lines.append("\nВерни JSON с гипотезами (только подтверждённые кодом).")
    return "\n".join(lines)


def llm_hypotheses_direct(ctx: CodeContext, cfg: SecurityConfig, llm: SecurityLlm,
                          candidates: list[VulnHypothesis]) -> list[VulnHypothesis]:
    """One-shot LLM review over a context pack (no tool loop).

    Free Groq has 8k tokens/min: an 8-step tool loop either hits 429 or the
    model keeps re-reading files. This mode gives the model the useful context
    (entry points, sinks, code windows around candidates) in a single request.
    """
    answer = llm.chat_json(
        [{"role": "system", "content": _DIRECT_SYSTEM},
         {"role": "user", "content": _direct_prompt(ctx, cfg, candidates)}],
        max_tokens=2400,
    )
    raw = answer.get("hypotheses")
    if raw is None and str(answer.get("action") or "") == "submit":
        raw = (answer.get("args") or {}).get("hypotheses")
    return _normalize_hypotheses(raw or [], ctx)


def _merge_hypotheses(llm_hypotheses: list[VulnHypothesis],
                      deterministic: list[VulnHypothesis]) -> list[VulnHypothesis]:
    """LLM output plus strong deterministic findings it did not mention."""
    keys = {(h.vuln_class.value, h.file, h.line) for h in llm_hypotheses}
    merged = list(llm_hypotheses)
    for hypothesis in deterministic:
        if hypothesis.confidence < 0.6:
            continue
        key = (hypothesis.vuln_class.value, hypothesis.file, hypothesis.line)
        if key not in keys:
            merged.append(hypothesis)
            keys.add(key)
    return merged


# ------------------------------------------------------------------- public
def review_repository(
    root: Path,
    findings: list[Finding] | None = None,
    cfg: SecurityConfig | None = None,
    *,
    use_llm: bool = True,
    language: str | None = None,
) -> dict[str, Any]:
    """Run the code review stage; returns hypotheses + new findings + meta.

    Falls back to the deterministic reviewer when the LLM is unavailable or
    fails, so the stage never blocks a scan.
    """
    from app.security.config import load_security_config

    cfg = cfg or load_security_config()
    root = Path(root)
    meta: dict[str, Any] = {"enabled": cfg.review_enabled, "status": "skipped"}
    if not cfg.review_enabled:
        return {"hypotheses": [], "findings": [], "meta": meta}

    try:
        total = sum(1 for p in root.rglob("*")
                    if p.is_file() and p.suffix in LANGUAGES
                    and not any(part in {".venv", "venv", "node_modules", "__pycache__"}
                                for part in p.parts))
        if total > cfg.review_max_repo_files:
            return {"hypotheses": [], "findings": [],
                    "meta": {**meta, "status": "skipped",
                             "reason": f"repo too large for review: {total} files"}}
        ctx = build_code_context(root, language, cfg)
    except Exception as exc:  # noqa: BLE001
        logger.exception("code context failed")
        return {"hypotheses": [], "findings": [], "meta": {**meta, "status": "failed", "error": str(exc)}}

    deterministic = deterministic_hypotheses(ctx, cfg)
    hypotheses: list[VulnHypothesis] = []
    mode = "deterministic"
    llm = SecurityLlm(cfg)
    meta["llm"] = llm.info()
    if use_llm and llm.available:
        try:
            if cfg.review_tool_mode == "on":
                hypotheses = llm_hypotheses(ctx, cfg, llm)
                mode = "llm" if hypotheses else "llm-empty"
            else:
                hypotheses = llm_hypotheses_direct(ctx, cfg, llm, deterministic)
                mode = "llm-direct" if hypotheses else "llm-empty"
            if hypotheses:
                hypotheses = _merge_hypotheses(hypotheses, deterministic)
        except SecurityLlmError as exc:
            logger.warning("LLM review failed (%s); falling back to deterministic", exc)
            meta["llm_error"] = str(exc)[:1000]
    if not hypotheses:
        hypotheses = deterministic

    hypotheses = hypotheses[: cfg.review_max_hypotheses]
    existing = {(f.cwe, f.file, f.line) for f in (findings or [])}
    fresh = [h for h in hypotheses if (h.cwe, h.file, h.line) not in existing]
    # one review finding per route (or file): many sink hits in the same flow
    # would otherwise duplicate the same issue.
    best: dict[tuple, VulnHypothesis] = {}
    for h in fresh:
        key = (h.vuln_class.value, h.endpoint or h.file, h.param)
        if key not in best or h.confidence > best[key].confidence:
            best[key] = h
    review_findings = hypotheses_to_findings(list(best.values()), include_sast=True)
    meta.update({
        "status": "completed",
        "mode": mode,
        "files": len(ctx.index.files),
        "functions": len(ctx.functions()),
        "entrypoints": len(ctx.entrypoints),
        "sinks": len(ctx.sinks),
        "hypotheses": len(hypotheses),
        "llm_model": cfg.llm_model if mode.startswith("llm") else None,
        "llm_provider": cfg.llm_provider if mode.startswith("llm") else None,
    })
    return {"hypotheses": hypotheses, "findings": review_findings, "meta": meta}


def hypotheses_to_findings(hypotheses: list[VulnHypothesis],
                           *, include_sast: bool = False) -> list[Finding]:
    out: list[Finding] = []
    for h in hypotheses:
        if h.source == Source.sast and not include_sast:
            continue  # already reported by the SAST engine
        # weak hypotheses stay in the report as "unverified", not as findings
        if h.confidence < 0.5 and h.vuln_class != VulnClass.hardcoded_secret:
            continue
        out.append(Finding(
            id=f"review-{h.id}",
            title=h.title,
            description=h.description,
            severity=FindingSeverity(h.severity.value),
            cwe=h.cwe,
            file=h.file,
            line=h.line,
            rule_id=f"review/{h.vuln_class.value}",
            source="llm-review" if h.meta.get("reviewer") == "llm" else "review-agent",
            language="python",
            remediation="Проверьте путь данных и добавьте валидацию/параметризацию/экранирование.",
            extra={"hypothesis_id": h.id, "endpoint": h.endpoint, "param": h.param,
                   "confidence": h.confidence,
                   "fix_prompt": (f"Исправь {h.vuln_class.value} ({h.cwe}) в {h.file}:{h.line}: "
                                  f"{h.description[:300]}")},
        ))
    return out
