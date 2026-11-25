from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.dast.agent.config import PentestConfig, load_pentest_config
from app.dast.agent.planner import LlmPlanner
from app.dast.agent.probes import ProbeResult
from app.dast.agent.target import TargetClient
from app.dast.agent.tools import AgentState, ToolRegistry
from app.models.finding import Finding, Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
}


@dataclass
class PentestRun:
    target_url: str
    mode: str
    findings: list[Finding] = field(default_factory=list)
    probes: list[ProbeResult] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def meta(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "target_url": self.target_url,
            "pages": self.pages,
            "endpoints": self.endpoints,
            "steps": len(self.steps),
            "stats": self.stats,
        }


def _dedupe(results: list[ProbeResult]) -> list[ProbeResult]:
    seen: set[tuple[str, str, str]] = set()
    out: list[ProbeResult] = []
    for r in results:
        key = (r.kind, r.url, r.payload[:40])
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def to_findings(results: list[ProbeResult]) -> list[Finding]:
    findings: list[Finding] = []
    for i, r in enumerate(_dedupe(results)):
        findings.append(Finding(
            id=f"pentest-{i:03d}",
            title=r.title,
            description=(
                f"{r.title}. Обнаружено агентом при активной проверке "
                f"(payload: {r.payload or '—'})."
            ),
            severity=_SEVERITY_MAP.get(r.severity, Severity.unknown),
            cwe=r.cwe,
            file=None,
            line=None,
            rule_id=f"pentest/{r.kind}",
            source="pentest",
            language="http",
            remediation=(
                "Подтвердите находку вручную, затем устраните причину: параметризация "
                "запросов, экранирование вывода, канонизация путей, валидация redirect-URL."
            ),
            extra={
                "url": r.url,
                "payload": r.payload,
                "evidence": r.evidence,
                "request": r.request,
                "response": r.response,
                "confidence": r.confidence,
                "tags": r.tags,
            },
        ))
    return findings


def _deterministic_plan(tools: ToolRegistry, state: AgentState, cfg: PentestConfig,
                        *, skip_crawl: bool = False) -> None:
    if not skip_crawl:
        tools.call("crawl", {})
    tools.call("probe_headers", {})
    if state.pages:
        tools.call("probe_errors", {})
    endpoints = state.endpoints[:6]
    for ep in endpoints:
        tools.call("probe_endpoint", {
            "url": ep["url"], "method": ep["method"],
            "params": ep["params"], "kind": ep.get("kind", "query"),
        })
    tools.call("finish", {"reason": "детерминированный план выполнен"})


def _llm_loop(tools: ToolRegistry, state: AgentState, cfg: PentestConfig,
              planner: LlmPlanner) -> None:
    history: list[dict[str, Any]] = state.steps
    for step in range(cfg.max_steps):
        if not state.client.budget.can_request():
            state.finished = True
            state.finish_reason = "budget exhausted"
            break
        try:
            action = planner.next_action(state, history)
        except Exception as exc:  # noqa: BLE001 - fall back, never fail the scan
            logger.warning("LLM planner failed (%s); falling back to deterministic plan", exc)
            state.steps.append({"tool": "planner-fallback", "args": {}, "result": str(exc)})
            _deterministic_plan(tools, state, cfg, skip_crawl=bool(state.endpoints))
            return
        name = str(action.get("tool") or "")
        args = action.get("args") or {}
        if action.get("thought"):
            state.steps.append({"tool": "thought", "args": {}, "result": action["thought"]})
        tools.call(name, args)
        if state.finished:
            break


def run_pentest(
    target_url: str,
    *,
    use_llm: bool = True,
    overrides: dict[str, Any] | None = None,
) -> PentestRun:
    cfg = load_pentest_config(overrides)
    client = TargetClient(target_url, cfg)
    state = AgentState(client=client, cfg=cfg)
    tools = ToolRegistry(state)
    planner = LlmPlanner(cfg)
    mode = "llm" if (use_llm and planner.available) else "deterministic"

    try:
        if mode == "llm":
            logger.info("pentest agent: LLM planner (%s)", cfg.llm_model)
            _llm_loop(tools, state, cfg, planner)
        else:
            logger.info("pentest agent: deterministic plan")
            _deterministic_plan(tools, state, cfg)
    finally:
        stats = client.stats()
        client.close()

    findings = to_findings(state.results)
    return PentestRun(
        target_url=target_url,
        mode=mode,
        findings=findings,
        probes=_dedupe(state.results),
        steps=state.steps,
        pages=state.pages,
        endpoints=state.endpoints,
        stats={**stats, "finished": state.finished, "reason": state.finish_reason},
    )
