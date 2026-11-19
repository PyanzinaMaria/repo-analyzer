"""Entry-point detection by patterns (spec §5.3)."""

from __future__ import annotations

import re

from app.context.index import FileInfo, FuncInfo, SnapshotIndex

PY_ROUTE_DECORATOR = re.compile(
    r"@\s*[\w.]*\.(route|get|post|put|delete|patch|head|options|websocket|api_route|endpoint)\s*\(", re.I)
PY_OTHER_DECORATOR = re.compile(
    r"@\s*([\w.]*\.)?(api_view|action|view_config|expose|shared_task|task|command|group|"
    r"login_required|permission_required|csrf_exempt|require_http_methods|require_POST|require_GET|"
    r"app\.cli\.command|click\.command|receiver)\b", re.I)
PY_VIEW_FILE = re.compile(r"(^|/)(views?|api|apis|endpoints|routes|handlers|controllers?|resources)(\.py|/)")
DJANGO_METHODS = {"get", "post", "put", "patch", "delete", "dispatch", "form_valid", "get_queryset", "get_object"}

JS_ROUTE_NAME = re.compile(
    r"^(app|router|server|api|fastify|route|r|routes|express|koa|instance)\.(get|post|put|delete|del|patch|all|"
    r"use|options|head|route|register|ws)\(", re.I)
JS_NEST_DECORATOR = re.compile(r"@(Get|Post|Put|Delete|Patch|All|Options|Head|MessagePattern|EventPattern)\s*\(")
JS_HANDLER_NAME = re.compile(r"(handler|middleware|controller|route)$", re.I)


def _python_entry(fn: FuncInfo, fi: FileInfo) -> str | None:
    if PY_ROUTE_DECORATOR.search(fn.header):
        return "route"
    m = PY_OTHER_DECORATOR.search(fn.header)
    if m:
        return "decorated:" + m.group(2).lower()
    sig = fn.header.split("\n")[-1] if fn.header else ""
    simple = fn.simple_name
    if PY_VIEW_FILE.search(fn.file):
        if re.search(r"def\s+\w+\s*\(\s*(self\s*,\s*)?request\b", sig):
            return "django_view"
        if "." in fn.name and simple in DJANGO_METHODS:
            return "class_view_method"
    if simple in ("lambda_handler", "handler") and re.search(r"\(\s*event\s*,\s*context", sig):
        return "lambda"
    if simple == "main" and fn.name == "main":
        return "cli_main"
    return None


def _js_entry(fn: FuncInfo, fi: FileInfo) -> str | None:
    if JS_ROUTE_NAME.search(fn.name):
        return "route"
    if JS_NEST_DECORATOR.search(fn.header):
        return "nest_route"
    parts = fn.name.split(".")
    # `module.exports = function () {}` / `module.exports.x = function` / `exports.x = function`
    if parts[0] == "module" and len(parts) in (2, 3) and parts[1] == "exports":
        return "exported_api"
    if parts[0] == "exports" and len(parts) == 2:
        return "exported_api"
    if "<" in fn.name or not fi.exports:
        return None   # anonymous callbacks are not API entry points by themselves
    if len(parts) == 1 and parts[0] in fi.exports:
        return "exported_api"
    if len(parts) == 2 and parts[0] in fi.exports and not parts[1].startswith("_"):
        return "exported_api"   # public method of an exported class/object
    return None


def detect_entrypoints(idx: SnapshotIndex, package_main: str | None = None) -> dict[str, str]:
    """function id -> entry kind."""
    out: dict[str, str] = {}
    for fi in idx.files.values():
        for fn in fi.functions:
            kind = _python_entry(fn, fi) if fi.language == "python" else _js_entry(fn, fi)
            if kind is None and package_main and fi.file == package_main and "." not in fn.name \
                    and not fn.name.startswith("<"):
                kind = "package_main_top_level"
            if kind:
                out[fn.id] = kind
    return out


def package_main(root) -> str | None:
    """`main` field of package.json at the snapshot root (npm packages: public API lives there)."""
    import json
    from pathlib import Path

    pj = Path(root) / "package.json"
    try:
        main = json.loads(pj.read_text(encoding="utf-8")).get("main") or "index.js"
    except (OSError, ValueError):
        return None
    main = main.lstrip("./")
    if not main.endswith((".js", ".cjs", ".mjs", ".ts")):
        main = main.rstrip("/") + ("/index.js" if (Path(root) / main).is_dir() else ".js")
    return main
