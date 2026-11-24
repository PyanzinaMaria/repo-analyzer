"""OpenAPI spec discovery/generation for OFFAT, which can only fuzz what a spec describes.

OWASP Benchmark corpora ship no spec, so `routes_to_openapi` builds one from the servlet/
Flask route declarations in the pinned snapshot worktree (route -> test-case URL -> ground
truth). RealVuln apps are probed for a live spec at the usual documentation endpoints.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx

_SPEC_CANDIDATES = ("/openapi.json", "/swagger.json", "/v2/swagger.json", "/v3/api-docs",
                    "/api-docs", "/apispec.json", "/swagger/doc.json")

_JAVA_ROUTE = re.compile(r'@WebServlet\(\s*(?:value\s*=\s*)?"(/[^"]+)"')
_PY_ROUTE = re.compile(r"""@app\.route\(\s*['"]([^'"]+)['"]\s*(?:,\s*methods\s*=\s*\[([^\]]*)\])?""")

GENERIC_PARAM = "param"


def discover_routes(worktree: Path, kind: str) -> dict[str, list[str]]:
    """path -> [GET, POST]; scanned from the snapshot worktree (route table = test-case table)."""
    routes: dict[str, list[str]] = {}
    if kind == "owasp-java":
        for f in (worktree / "src" / "main" / "java").rglob("*.java"):
            for m in _JAVA_ROUTE.finditer(f.read_text(encoding="utf-8", errors="replace")):
                routes.setdefault(m.group(1), ["GET", "POST"])
    elif kind == "owasp-python":
        for f in (worktree / "testcode").glob("*.py"):
            text = f.read_text(encoding="utf-8", errors="replace")
            for m in _PY_ROUTE.finditer(text):
                path, methods = m.group(1), m.group(2) or "'GET'"
                names = [x.strip().strip("'\"") for x in methods.split(",") if x.strip()]
                routes.setdefault(path, names or ["GET"])
    return {p: ms for p, ms in sorted(routes.items()) if "BenchmarkTest" in p}


def routes_to_openapi(routes: dict[str, list[str]], *, title: str) -> dict:
    """Minimal OpenAPI 3.0 doc: one cookie/query/body fuzzing parameter per test endpoint."""
    paths = {}
    for path, methods in routes.items():
        test = path.rsplit("/", 1)[-1]
        ops = {}
        for m in methods:
            op = {
                "operationId": f"{test.lower()}_{m.lower()}",
                "parameters": [
                    {"name": GENERIC_PARAM, "in": "query", "required": False,
                     "schema": {"type": "string", "default": "noStringValue"}},
                    {"name": test, "in": "cookie", "required": False,
                     "schema": {"type": "string", "default": "noStringValue"}},
                ],
            }
            if m.upper() == "POST":
                op["requestBody"] = {"required": False, "content": {
                    "application/x-www-form-urlencoded": {"schema": {
                        "type": "object", "properties": {GENERIC_PARAM: {"type": "string"}}}}}}
            ops[m.lower()] = op
        paths[path] = ops
    return {"openapi": "3.0.1", "info": {"title": title, "version": "bench"},
            "servers": [{"url": "/"}], "paths": paths}


def probe_openapi(base_url: str, timeout: int = 20) -> dict | None:
    """Probe common spec endpoints of a live app; None if it publishes none."""
    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as client:
        for path in _SPEC_CANDIDATES:
            try:
                r = client.get(base_url.rstrip("/") + path)
            except httpx.HTTPError:
                continue
            if r.status_code != 200:
                continue
            try:
                data = r.json()
            except ValueError:
                continue
            if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                return data
    return None


def write_spec(doc: dict, dest: Path) -> Path:
    import json

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(doc), encoding="utf-8")
    return dest
