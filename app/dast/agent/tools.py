from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from app.dast.agent.crawl import discover
from app.dast.agent.probes import (
    ProbeResult,
    probe_endpoint,
    probe_errors,
    probe_headers,
)
from app.dast.agent.target import TargetClient


@dataclass
class AgentState:
    client: TargetClient
    cfg: Any
    pages: list[str] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)
    results: list[ProbeResult] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)
    finished: bool = False
    finish_reason: str = ""

    def add(self, results: list[ProbeResult]) -> None:
        self.results.extend(results)

    def summary(self) -> dict[str, Any]:
        return {
            "pages": self.pages,
            "endpoints": self.endpoints,
            "findings": len(self.results),
            "requests": self.client.budget.requests,
            "elapsed_seconds": round(self.client.budget.elapsed, 2),
            "finished": self.finished,
            "reason": self.finish_reason,
        }


def _tool_schemas() -> list[dict[str, Any]]:
    return [
        {
            "name": "crawl",
            "description": "Fetch the target root page and discover same-origin links and forms.",
            "input_schema": {"type": "object", "properties": {"max_pages": {"type": "integer"}}},
        },
        {
            "name": "probe_headers",
            "description": "Check security headers (CSP, HSTS, X-Frame-Options, ...).",
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "probe_errors",
            "description": "Look for stack traces / framework error pages on discovered pages.",
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "probe_endpoint",
            "description": "Run the active payload probes (SQLi, XSS, path traversal, open redirect, "
                           "command injection) against one endpoint and its parameters.",
            "input_schema": {
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": ["GET", "POST"]},
                    "params": {"type": "object", "additionalProperties": {"type": "string"}},
                    "kind": {"type": "string", "enum": ["query", "form"]},
                },
            },
        },
        {
            "name": "send_request",
            "description": "Send one GET/POST request and return status, headers and a body snippet.",
            "input_schema": {
                "type": "object",
                "required": ["method", "url"],
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "HEAD"]},
                    "url": {"type": "string"},
                    "params": {"type": "object", "additionalProperties": {"type": "string"}},
                    "data": {"type": "object", "additionalProperties": {"type": "string"}},
                },
            },
        },
        {
            "name": "finish",
            "description": "Stop the pentest and produce the report.",
            "input_schema": {"type": "object", "properties": {"reason": {"type": "string"}}},
        },
    ]


class ToolRegistry:
    """Tool layer shared by the LLM agent and the MCP server."""

    def __init__(self, state: AgentState) -> None:
        self.state = state
        self._impl: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "crawl": self._crawl,
            "probe_headers": self._probe_headers,
            "probe_errors": self._probe_errors,
            "probe_endpoint": self._probe_endpoint,
            "send_request": self._send_request,
            "finish": self._finish,
        }

    def schemas(self) -> list[dict[str, Any]]:
        return _tool_schemas()

    def call(self, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        if name not in self._impl:
            return {"error": f"unknown tool: {name}"}
        try:
            out = self._impl[name](args or {})
        except Exception as exc:  # noqa: BLE001 - the agent must survive tool errors
            out = {"error": f"{type(exc).__name__}: {exc}"}
        self.state.steps.append({"tool": name, "args": args or {}, "result": out})
        return out

    # ------------------------------------------------------------------ tools
    def _crawl(self, args: dict[str, Any]) -> dict[str, Any]:
        max_pages = int(args.get("max_pages") or self.state.cfg.max_pages)
        pages, eps = discover(self.state.client, max_pages=max_pages,
                              max_params=self.state.cfg.max_params)
        self.state.pages = pages
        self.state.endpoints = [
            {"url": e.url, "method": e.method, "params": e.params, "kind": e.kind}
            for e in eps[:20]
        ]
        return {
            "pages": pages,
            "endpoints": [f"{e.method} {e.url} [{','.join(e.params)}]" for e in eps[:20]],
            "endpoint_count": len(eps),
        }

    def _probe_headers(self, args: dict[str, Any]) -> dict[str, Any]:
        results = probe_headers(self.state.client, "/")
        self.state.add(results)
        return {"found": [r.title for r in results]}

    def _probe_errors(self, args: dict[str, Any]) -> dict[str, Any]:
        pages = self.state.pages or ["/"]
        results = probe_errors(self.state.client, pages[: self.state.cfg.max_pages])
        self.state.add(results)
        return {"found": [r.title for r in results]}

    def _probe_endpoint(self, args: dict[str, Any]) -> dict[str, Any]:
        from app.dast.agent.crawl import Endpoint

        url = str(args.get("url") or "/")
        method = str(args.get("method") or "GET").upper()
        params = {str(k): str(v) for k, v in (args.get("params") or {}).items()}
        if not params:
            return {"error": "params are empty: nothing to inject"}
        ep = Endpoint(url=url, method=method, params=params,
                      kind=str(args.get("kind") or "query"))
        results = probe_endpoint(self.state.client, ep, max_params=self.state.cfg.max_params)
        self.state.add(results)
        return {
            "url": url,
            "method": method,
            "params": list(params),
            "found": [{"kind": r.kind, "title": r.title, "payload": r.payload} for r in results],
        }

    def _send_request(self, args: dict[str, Any]) -> dict[str, Any]:
        method = str(args.get("method") or "GET").upper()
        if method not in {"GET", "POST", "HEAD"}:
            return {"error": "only GET/POST/HEAD are allowed"}
        resp = self.state.client.request(
            method,
            str(args.get("url") or "/"),
            params=args.get("params") or None,
            data=args.get("data") or None,
            allow_redirects=False,
        )
        return {
            "status": resp.status,
            "headers": dict(list(resp.headers.items())[:10]),
            "body_snippet": resp.snippet(400),
        }

    def _finish(self, args: dict[str, Any]) -> dict[str, Any]:
        self.state.finished = True
        self.state.finish_reason = str(args.get("reason") or "model finished")
        return {"finished": True}


def tools_prompt() -> str:
    """Compact tool catalog for the LLM system prompt."""
    lines = []
    for t in _tool_schemas():
        props = t["input_schema"].get("properties", {})
        args = ", ".join(props) if props else "no arguments"
        lines.append(f"- {t['name']}({args}): {t['description']}")
    return "\n".join(lines)


def parse_action(text: str) -> dict[str, Any]:
    """Extract {tool, args} from a model answer (tolerates code fences)."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no JSON object in model answer")
    data = json.loads(text[start:end + 1])
    if "tool" not in data:
        raise ValueError("model answer has no 'tool' field")
    return {"tool": data["tool"], "args": data.get("args") or {}}
