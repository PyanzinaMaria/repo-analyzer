from __future__ import annotations

"""Hypothesis-driven dynamic verification.

For every hypothesis the verifier builds concrete probe plans
(plugin x payload x strategy), executes them against the running target and
classifies the result: confirmed / refuted / uncertain / skipped.

Unlike a blind crawl it targets the exact endpoint and parameter that the code
review identified, and it uses the target's own attack surface (forms/links)
only when the hypothesis has no URL.
"""

import logging
from dataclasses import dataclass
from typing import Any

from app.dast.agent.config import PentestConfig
from app.dast.agent.crawl import discover
from app.dast.agent.target import TargetClient
from app.models.finding import Finding, Severity as FindingSeverity
from app.security.config import SecurityConfig
from app.security.judge import judge_verification
from app.security.llm import SecurityLlm
from app.security.models import (
    Detection,
    ProbePlan,
    Severity,
    Source,
    Verdict,
    Verification,
    VulnClass,
    VulnHypothesis,
)
from app.security.plugins import STATIC_ONLY, Plugin, plugins_for
from app.security.risk import priority_bucket, verification_risk
from app.security.strategies import apply_strategies

logger = logging.getLogger(__name__)

_SEV_ORDER = {Severity.info: 1, Severity.low: 2, Severity.medium: 3, Severity.high: 4,
              Severity.critical: 5}
_FINDING_SEV = {
    Severity.critical: FindingSeverity.critical,
    Severity.high: FindingSeverity.high,
    Severity.medium: FindingSeverity.medium,
    Severity.low: FindingSeverity.low,
    Severity.info: FindingSeverity.info,
}


@dataclass
class VerifyStats:
    requests: int = 0
    plans: int = 0
    confirmed: int = 0
    refuted: int = 0
    uncertain: int = 0
    skipped: int = 0
    elapsed: float = 0.0
    auth: bool = False
    ok_responses: int = 0
    unreachable: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests, "plans": self.plans,
            "confirmed": self.confirmed, "refuted": self.refuted,
            "uncertain": self.uncertain, "skipped": self.skipped,
            "elapsed_seconds": round(self.elapsed, 2), "authenticated": self.auth,
            "ok_responses": self.ok_responses, "unreachable": self.unreachable,
        }


def _max_sev(a: Severity, b: Severity) -> Severity:
    return a if _SEV_ORDER[a] >= _SEV_ORDER[b] else b


class Verifier:
    def __init__(self, target_url: str, cfg: SecurityConfig,
                 llm: SecurityLlm | None = None) -> None:
        self.cfg = cfg
        self.target_url = target_url
        self.llm = llm or SecurityLlm(cfg)
        self.client = TargetClient(target_url, PentestConfig(
            allow_private_targets=cfg.verify_allow_private,
            max_requests=cfg.verify_max_requests,
            max_seconds=cfg.verify_max_seconds,
            delay_seconds=cfg.verify_delay,
        ))
        self.stats = VerifyStats()
        self.auth_ok = False
        self._baselines: dict[tuple[str, str], Any] = {}
        self._crawl_cache: list[dict[str, Any]] | None = None
        self._pages: list[str] = []
        self._resolved: dict[str, str] = {}
        self._enabled_plugins = set(cfg.plugins) if cfg.plugins else None

    def _resolve_endpoint(self, endpoint: str) -> str:
        """Map a route inferred from code to the real path.

        Blueprint prefixes can be missed for unusual setups, so if the inferred
        path 404s we look for a crawled endpoint with the same suffix.
        """
        if endpoint.startswith(("http://", "https://")) or endpoint in self._resolved:
            return self._resolved.get(endpoint, endpoint)
        resolved = endpoint
        try:
            resp = self.client.request("GET", endpoint)
            if resp.status >= 400:
                want = endpoint.rstrip("/")
                for ep in self._crawl():
                    path = "/" + ep["url"].split("/", 3)[-1] if "://" in ep["url"] else ep["url"]
                    path = path.rstrip("/")
                    if path.endswith(want) or want.endswith(path):
                        resolved = path
                        break
        except Exception as exc:  # noqa: BLE001 - resolution is best-effort
            logger.debug("endpoint resolution failed for %s: %s", endpoint, exc)
        self._resolved[endpoint] = resolved
        return resolved

    # ------------------------------------------------------------------ crawl
    def _crawl(self) -> list[dict[str, Any]]:
        if self._crawl_cache is not None:
            return self._crawl_cache
        try:
            pages, endpoints = discover(self.client, max_pages=8,
                                        max_params=self.cfg.verify_max_hypotheses)
            self._pages = list(pages)
            self._crawl_cache = [
                {"url": e.url, "method": e.method, "params": e.params, "kind": e.kind}
                for e in endpoints
            ]
        except Exception as exc:  # noqa: BLE001 - crawl is best-effort
            logger.warning("crawl for verification failed: %s", exc)
            self._crawl_cache = []
        return self._crawl_cache

    def _crawl_params(self, endpoint: str) -> list[str]:
        """Form/query fields of the crawled endpoint matching a code route."""
        want = endpoint.rstrip("/")
        for ep in self._crawl():
            path = "/" + ep["url"].split("/", 3)[-1] if "://" in ep["url"] else ep["url"]
            path = path.rstrip("/")
            if not path or not want:
                continue
            if path.endswith(want) or want.endswith(path):
                params = ep.get("params") or {}
                return list(params) if isinstance(params, dict) else list(params)
        return []

    def _find_endpoint(self, plugin: Plugin, hypothesis: VulnHypothesis) -> dict[str, Any] | None:
        """Best endpoint for a hypothesis that has no explicit URL."""
        endpoints = self._crawl()
        # 1) endpoint whose param matches the plugin's hints
        for ep in endpoints:
            for param in ep["params"]:
                if plugin.matches_param(param):
                    return {**ep, "param": param}
        # 2) same param name as the hypothesis
        if hypothesis.param:
            for ep in endpoints:
                if hypothesis.param in ep["params"]:
                    return {**ep, "param": hypothesis.param}
        # 3) first endpoint with at least one param
        for ep in endpoints:
            if ep["params"]:
                return {**ep, "param": next(iter(ep["params"]))}
        return None

    # ------------------------------------------------------------------- auth
    def _ensure_auth(self) -> None:
        """Log in once so protected endpoints can be verified."""
        if not self.cfg.auth_enabled or not self.cfg.auth_username:
            return
        try:
            if self.cfg.auth_register_url:
                self.client.request("POST", self.cfg.auth_register_url, data={
                    self.cfg.auth_username_field: self.cfg.auth_username,
                    self.cfg.auth_password_field: self.cfg.auth_password,
                    self.cfg.auth_email_field: self.cfg.auth_email,
                })
            self.client.request("POST", self.cfg.auth_login_url, data={
                self.cfg.auth_username_field: self.cfg.auth_username,
                self.cfg.auth_password_field: self.cfg.auth_password,
            })
            self.auth_ok = len(self.client.client.cookies) > 0
        except Exception as exc:  # noqa: BLE001 - auth is best-effort
            logger.warning("authentication for verification failed: %s", exc)

    # ------------------------------------------------------------------ plans
    def _plans_for(self, hypothesis: VulnHypothesis) -> list[ProbePlan]:
        plugins = plugins_for(hypothesis.vuln_class)
        if self._enabled_plugins is not None:
            plugins = [p for p in plugins if p.id in self._enabled_plugins]
        plans: list[ProbePlan] = []

        for plugin in plugins:
            target: dict[str, Any] | None
            if plugin.transport == "target":
                urls = ["/"]
                if plugin.id == "error_disclosure":
                    if not self._pages:
                        self._crawl()
                    urls += [p for p in (self._pages or []) if p != "/"][:8]
                for url in urls:
                    for strategy, value in apply_strategies("", tuple(self.cfg.strategies)):
                        plans.append(ProbePlan(
                            hypothesis_id=hypothesis.id, plugin=plugin.id, strategy=strategy,
                            url=url, method="GET", param="", payload=value,
                            cwe=plugin.cwe,
                            severity=_max_sev(plugin.severity, hypothesis.severity),
                            meta={"transport": "target", "expects_param": False},
                        ))
                continue
            elif hypothesis.endpoint:
                param = hypothesis.param or (
                    next((p for p in (hypothesis.meta.get("params") or []) if p), None)
                )
                if plugin.requires_param and not param:
                    param = self._guess_param(plugin, hypothesis)
                if plugin.requires_param and not param:
                    continue
                # LLM hypotheses often carry only the injected field; fill the
                # rest of the form from the crawled endpoint so the route does
                # not fail on a missing key before reaching the vulnerable code.
                params = list(hypothesis.meta.get("params") or [])
                if not params:
                    params = self._crawl_params(hypothesis.endpoint)
                target = {"url": self._resolve_endpoint(hypothesis.endpoint),
                          "method": (hypothesis.method or "GET").upper(),
                          "param": param or "",
                          "params": params}
            else:
                # a static hypothesis without a route mapping cannot be "pressed":
                # guessing an unrelated endpoint would only produce false positives.
                if hypothesis.source != Source.crawl:
                    continue
                target = self._find_endpoint(plugin, hypothesis)
                if target is None:
                    continue

            methods = [target["method"]]
            if target["method"] == "GET" and plugin.transport in {"xml", "form"}:
                methods = ["POST"]
            strategies = tuple(self.cfg.strategies) + tuple(plugin.extra_strategies)
            # encoded payloads are not executable for XSS / prompt injection:
            # a percent-encoded `<script>` in the body is not a vulnerability.
            if plugin.id in {"xss", "prompt_injection"}:
                strategies = ("raw",)
            payloads = plugin.payload_list()
            variants: list[tuple[str, str]] = []
            for payload in payloads:
                variants.extend(apply_strategies(payload, strategies))
            for strategy, value in variants[:8]:
                if any(k in str(target["url"]).lower() for k in ("logout", "signout")):
                    continue  # probing a logout endpoint would kill the session
                plans.append(ProbePlan(
                    hypothesis_id=hypothesis.id, plugin=plugin.id, strategy=strategy,
                    url=str(target["url"]), method=methods[0], param=str(target["param"]),
                    payload=value, cwe=plugin.cwe, severity=_max_sev(plugin.severity, hypothesis.severity),
                    meta={"transport": plugin.transport, "expects_param": plugin.requires_param,
                          "params": list(target.get("params") or [])},
                ))
        return plans

    def _guess_param(self, plugin: Plugin, hypothesis: VulnHypothesis) -> str | None:
        candidates = list(hypothesis.meta.get("params") or [])
        for name in candidates:
            if plugin.matches_param(name):
                return str(name)
        return str(candidates[0]) if candidates else None

    # -------------------------------------------------------------- execution
    def _form_data(self, plan: ProbePlan, value: str) -> dict[str, str]:
        """Fill every known form field so the route does not fail on a missing key."""
        data = {str(p): "test" for p in (plan.meta.get("params") or []) if p}
        if plan.param:
            data[plan.param] = value
        if not data:
            data["x"] = value
        return data

    def _baseline(self, plan: ProbePlan) -> Any:
        key = (plan.url, plan.method)
        if key in self._baselines:
            return self._baselines[key]
        if plan.method == "POST":
            resp = self.client.request("POST", plan.url, data=self._form_data(plan, "test"))
        else:
            resp = self.client.request("GET", plan.url, params={plan.param or "x": "test"})
        self._baselines[key] = resp
        return resp

    def _send(self, plan: ProbePlan, plugin: Plugin) -> Any:
        if plugin.transport == "xml":
            body = plugin.body_for(plan.payload) if hasattr(plugin, "body_for") else plan.payload
            return self.client.request("POST", plan.url, data=body,
                                      headers={"Content-Type": "application/xml"})
        if plugin.transport == "target":
            return self.client.request("GET", plan.url)
        if plan.method == "POST" or plugin.transport == "form":
            return self.client.request("POST", plan.url, data=self._form_data(plan, plan.payload))
        return self.client.request("GET", plan.url, params={plan.param: plan.payload})

    def _execute(self, hypothesis: VulnHypothesis, plugin: Plugin,
                 plans: list[ProbePlan]) -> Verification:
        best: Verification | None = None
        for plan in plans:
            try:
                baseline = self._baseline(plan)
                resp = self._send(plan, plugin)
            except RuntimeError as exc:  # budget exhausted / request rejected
                return Verification(
                    hypothesis_id=hypothesis.id, verdict=Verdict.skipped,
                    explanation=str(exc), plugin=plugin.id,
                )
            self.stats.plans += 1
            # the session may expire or be reset by another probe: re-auth once
            if (self.cfg.auth_enabled and self.auth_ok and
                    (resp.status in {401, 403} or
                     (resp.status in {301, 302, 303, 307, 308} and
                      "login" in (resp.headers.get("location") or "").lower()))):
                self._ensure_auth()
                resp = self._send(plan, plugin)
                self.stats.plans += 1
            if resp.error:
                continue
            detection = plugin.detect(resp, plan.payload, baseline)
            verification = Verification(
                hypothesis_id=hypothesis.id, verdict=Verdict.uncertain,
                severity=_max_sev(plugin.severity, hypothesis.severity),
                plugin=plugin.id, strategy=plan.strategy, url=resp.url,
                payload=plan.payload, request=f"{plan.method} {resp.url}",
                response=resp.snippet(400), evidence=detection.evidence,
                meta={"plan_id": plan.id, "detector": detection.kind,
                      "param": plan.param, "method": plan.method},
            )
            verification = judge_verification(hypothesis, plan, verification, detection,
                                              self.cfg, self.llm)
            if verification.verdict == Verdict.confirmed:
                return verification
            if best is None or (verification.confidence or 0) > (best.confidence or 0):
                best = verification
        if best is not None:
            return best
        return Verification(
            hypothesis_id=hypothesis.id, verdict=Verdict.uncertain,
            severity=hypothesis.severity, plugin=plugin.id,
            explanation="не удалось выполнить проверки (нет подходящего эндпоинта или запросы не прошли)",
        )

    # ------------------------------------------------------------------- main
    def verify(self, hypotheses: list[VulnHypothesis]) -> list[Verification]:
        self._ensure_auth()
        ordered = sorted(hypotheses, key=lambda h: (
            -_SEV_ORDER[h.severity], -h.confidence))
        # cheap target-level checks are never squeezed out by the hypothesis cap
        target_checks = [h for h in ordered
                         if h.vuln_class in {VulnClass.missing_headers, VulnClass.error_disclosure}]
        others = [h for h in ordered if h not in target_checks]
        selected = target_checks + others[: self.cfg.verify_max_hypotheses]
        verifications: list[Verification] = []
        target_level_done: set[str] = set()

        for hypothesis in selected:
            if hypothesis.vuln_class in STATIC_ONLY:
                verifications.append(Verification(
                    hypothesis_id=hypothesis.id, verdict=Verdict.skipped,
                    explanation="класс проверяется только статически",
                ))
                self.stats.skipped += 1
                continue
            plans = self._plans_for(hypothesis)
            if not plans:
                verifications.append(Verification(
                    hypothesis_id=hypothesis.id, verdict=Verdict.skipped,
                    explanation="нет эндпоинта/параметра для проверки (нужен запущенный таргет)",
                ))
                self.stats.skipped += 1
                continue
            if not self.client.budget.can_request():
                verifications.append(Verification(
                    hypothesis_id=hypothesis.id, verdict=Verdict.skipped,
                    explanation="бюджет запросов исчерпан",
                ))
                self.stats.skipped += 1
                continue

            plugin = plugins_for(hypothesis.vuln_class)[0]
            # target-level plugins are checked once per target
            if plugin.transport == "target":
                if plugin.id in target_level_done:
                    continue
                target_level_done.add(plugin.id)
                if plugin.id != "error_disclosure":
                    plans = plans[:1]

            verification = self._execute(hypothesis, plugin, plans)
            verifications.append(verification)
            if verification.verdict == Verdict.confirmed:
                self.stats.confirmed += 1
            elif verification.verdict == Verdict.refuted:
                self.stats.refuted += 1
            elif verification.verdict == Verdict.skipped:
                self.stats.skipped += 1
            else:
                self.stats.uncertain += 1
            if (self.client.budget.ok_responses == 0
                    and self.client.budget.failed_requests >= 5):
                # target is down: do not burn the remaining budget on it
                self.stats.unreachable = True
                logger.warning("target unreachable after %s failed requests",
                               self.client.budget.failed_requests)
                break

        self.stats.requests = self.client.budget.requests
        self.stats.ok_responses = self.client.budget.ok_responses
        self.stats.elapsed = self.client.budget.elapsed
        self.stats.auth = self.auth_ok
        self.client.close()
        return verifications


def crawl_hypotheses(
    target_url: str,
    cfg: SecurityConfig,
    *,
    covered: set[tuple[str, str | None]] | None = None,
) -> list[VulnHypothesis]:
    """Hypothesise over the live surface: every form/query parameter gets the
    plugin whose name hints match. Used when code review cannot map a route
    (fixtures, Go/Java handlers, dynamically generated routes)."""
    from app.security.plugins import select_plugins

    covered = covered or set()
    try:
        client = TargetClient(target_url, PentestConfig(
            allow_private_targets=cfg.verify_allow_private,
            max_requests=min(cfg.verify_max_requests, 60),
            max_seconds=min(cfg.verify_max_seconds, 60),
            delay_seconds=cfg.verify_delay,
        ))
        _pages, endpoints = discover(client, max_pages=cfg.crawl_max_pages)
        base = client.base_url
        client.close()
    except Exception as exc:  # noqa: BLE001 - crawl is best-effort
        logger.warning("crawl fallback failed: %s", exc)
        return []

    plugins = select_plugins(cfg.plugins or None)
    hypotheses: list[VulnHypothesis] = []
    for ep in endpoints:
        rel = ep.url.replace(base, "") or "/"
        for param in ep.params:
            for plugin in plugins:
                if plugin.transport == "target" or not plugin.matches_param(param):
                    continue
                if (rel.rstrip("/"), param) in covered:
                    continue
                hypotheses.append(VulnHypothesis(
                    vuln_class=plugin.vuln_class, source=Source.crawl,
                    title=f"{plugin.title} — параметр {param}",
                    description=f"Параметр {param} найден при обходе живой поверхности.",
                    confidence=0.5, severity=plugin.severity,
                    endpoint=rel, method=ep.method, param=param,
                    evidence=f"{ep.method} {rel} ({ep.kind})",
                    meta={"reviewer": "crawl", "params": list(ep.params)},
                ))
                if len(hypotheses) >= cfg.crawl_max_hypotheses:
                    return hypotheses
    return hypotheses


def target_level_hypotheses(target_url: str) -> list[VulnHypothesis]:
    """The baseline checks every target gets, regardless of code review."""
    return [
        VulnHypothesis(
            vuln_class=VulnClass.missing_headers, source=Source.crawl,
            title="Проверка security-заголовков", confidence=1.0, severity=Severity.low,
            endpoint="/", method="GET",
        ),
        VulnHypothesis(
            vuln_class=VulnClass.error_disclosure, source=Source.crawl,
            title="Проверка раскрытия ошибок", confidence=0.8, severity=Severity.low,
            endpoint="/", method="GET",
        ),
    ]


def verifications_to_findings(verifications: list[Verification],
                              hypotheses: list[VulnHypothesis]) -> list[Finding]:
    """One finding per confirmed (plugin, endpoint, parameter) — many hypotheses
    pointing at the same reachable flaw must not duplicate the report."""
    by_id = {h.id: h for h in hypotheses}
    groups: dict[tuple[str, str, str], list[tuple[Verification, VulnHypothesis | None]]] = {}
    for v in verifications:
        if v.verdict != Verdict.confirmed:
            continue
        path = (v.url or "").split("?")[0]
        key = (v.plugin or "", path, str(v.meta.get("param") or ""))
        groups.setdefault(key, []).append((v, by_id.get(v.hypothesis_id)))

    findings: list[Finding] = []
    for (plugin, path, param), items in groups.items():
        # prefer the plainest confirmed variant for the report (raw strategy,
        # shortest payload) — encoded variants are only bypass attempts.
        items.sort(key=lambda it: (
            -it[0].confidence,
            0 if it[0].strategy == "raw" else 1,
            len(it[0].payload or ""),
        ))
        v, h = items[0]
        related = sorted({f"{x.file}:{x.line}" for _, x in items if x and x.file})
        risk = verification_risk(v, h)
        findings.append(Finding(
            id=f"verify-{v.hypothesis_id}",
            title=f"{h.title if h else plugin} — подтверждено динамически",
            description=(v.explanation or "Уязвимость подтверждена активной проверкой.") +
                        (f" Гипотеза: {h.description}" if h and h.description else "") +
                        (f" Связанные места в коде: {', '.join(related)}." if related else ""),
            severity=_FINDING_SEV.get(v.severity, FindingSeverity.high),
            cwe=h.cwe if h else None,
            file=h.file if h else None,
            line=h.line if h else None,
            rule_id=f"pentest/{plugin}",
            source="pentest",
            language="http",
            remediation="Подтверждено на запущенном приложении; устраните причину и добавьте регрессионный тест.",
            extra={
                "hypothesis_id": v.hypothesis_id,
                "hypotheses": [x.id for _, x in items if x],
                "url": v.url, "param": param, "payload": v.payload, "evidence": v.evidence,
                "request": v.request, "response": v.response,
                "confidence": v.confidence, "judged_by": v.judged_by,
                "plugin": plugin, "strategy": v.strategy,
                "risk": risk, "priority": priority_bucket(risk),
            },
        ))
    return findings
