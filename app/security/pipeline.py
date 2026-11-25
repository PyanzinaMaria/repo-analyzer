from __future__ import annotations

"""End-to-end security pipeline: review code → hypotheses → verify on target.

Can run standalone (CLI, no web/worker) and is used by the scan orchestrator.
Every stage soft-fails: a missing LLM key, a dead target or a broken plugin
degrades the result instead of breaking the scan.
"""

import logging
import time
from pathlib import Path
from typing import Any

from app.models.finding import Finding
from app.security.code_review import review_repository
from app.security.config import SecurityConfig, load_security_config
from app.security.llm import SecurityLlm
from app.security.models import (
    SecurityRun,
    Source,
    Verdict,
    VulnHypothesis,
)
from app.security.risk import hypothesis_risk, priority_bucket, verification_risk
from app.security.sast_adapter import findings_to_hypotheses
from app.security.verifier import (
    Verifier,
    crawl_hypotheses,
    target_level_hypotheses,
    verifications_to_findings,
)

logger = logging.getLogger(__name__)


def _dedupe(hypotheses: list[VulnHypothesis]) -> list[VulnHypothesis]:
    seen: set[tuple[str, str | None, str | None]] = set()
    out: list[VulnHypothesis] = []
    for h in hypotheses:
        key = h.key()
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out


def prioritize(hypotheses: list[VulnHypothesis]) -> list[VulnHypothesis]:
    return sorted(hypotheses, key=lambda h: (-hypothesis_risk(h), -h.confidence))


def run_security_scan(
    repo: str | Path,
    target_url: str | None = None,
    *,
    findings: list[Finding] | None = None,
    cfg: SecurityConfig | None = None,
    use_llm: bool = True,
    language: str | None = None,
    include_target_checks: bool = True,
) -> SecurityRun:
    """Review the repository, then verify hypotheses against `target_url` (optional)."""
    started = time.perf_counter()
    cfg = cfg or load_security_config()
    repo_path = Path(repo).resolve()
    meta: dict[str, Any] = {"repo": str(repo_path), "status": "ok"}
    all_findings: list[Finding] = list(findings or [])

    # 1) static findings -> hypotheses
    hypotheses: list[VulnHypothesis] = []
    if cfg.from_sast and findings:
        hypotheses.extend(findings_to_hypotheses(findings))
    meta["from_sast"] = len(hypotheses)

    # 2) code review -> hypotheses (+ review findings)
    review = review_repository(repo_path, findings, cfg, use_llm=use_llm, language=language)
    hypotheses.extend(review["hypotheses"])
    review_findings: list[Finding] = review["findings"]
    meta["review"] = review["meta"]

    hypotheses = _dedupe(hypotheses)

    # 2b) crawl fallback: cover surface that code review could not map to a route
    if target_url and cfg.crawl_fallback:
        covered = {(h.endpoint.rstrip("/") if h.endpoint else None, h.param)
                   for h in hypotheses if h.endpoint}
        crawl_hs = crawl_hypotheses(target_url, cfg, covered=covered)
        hypotheses.extend(crawl_hs)
        hypotheses = _dedupe(hypotheses)
        meta["from_crawl"] = len(crawl_hs)

    hypotheses = prioritize(hypotheses)[: cfg.review_max_hypotheses + cfg.verify_max_hypotheses]
    if target_url and include_target_checks:
        hypotheses = _dedupe(hypotheses + target_level_hypotheses(target_url))

    # 3) dynamic verification
    verifications = []
    verify_meta: dict[str, Any] = {"status": "skipped", "reason": "no target url"}
    if target_url and cfg.verify_enabled and hypotheses:
        try:
            llm = SecurityLlm(cfg)
            verifier = Verifier(target_url, cfg, llm)
            to_verify = list(hypotheses)
            verifications = verifier.verify(to_verify)
            dynamic_findings = verifications_to_findings(verifications, to_verify)
            all_findings.extend(dynamic_findings)
            verify_meta = {"status": "ok", **verifier.stats.as_dict()}
            if verifier.stats.unreachable:
                verify_meta = {"status": "failed", "reason": "target unreachable",
                               **verifier.stats.as_dict()}
        except Exception as exc:  # noqa: BLE001 - verification must not break the scan
            logger.exception("security verification failed")
            verify_meta = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
    elif target_url and not hypotheses:
        verify_meta = {"status": "skipped", "reason": "no hypotheses"}

    # 4) only review findings that are not already represented by a confirmation
    seen_keys = {(f.cwe, f.file, f.line) for f in all_findings}
    for f in review_findings:
        if (f.cwe, f.file, f.line) not in seen_keys:
            all_findings.append(f)
            seen_keys.add((f.cwe, f.file, f.line))

    confirmed = sum(1 for v in verifications if v.verdict == Verdict.confirmed)
    # min_severity gates what lands in the report (promptfoo's minSeverity idea)
    sev_order = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    min_rank = sev_order.get(cfg.min_severity, 1)
    all_findings = [f for f in all_findings
                    if sev_order.get(f.severity.value, 3) >= min_rank]
    meta.update({
        "hypotheses": len(hypotheses),
        "sources": {s.value: sum(1 for h in hypotheses if h.source == s) for s in Source},
        "verifications": len(verifications),
        "confirmed": confirmed,
        "refuted": sum(1 for v in verifications if v.verdict == Verdict.refuted),
        "uncertain": sum(1 for v in verifications if v.verdict == Verdict.uncertain),
        "skipped": sum(1 for v in verifications if v.verdict == Verdict.skipped),
        "verification": verify_meta,
        "findings": len(all_findings),
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "llm_enabled": cfg.llm_enabled,
        "mode": review["meta"].get("mode"),
    })
    return SecurityRun(
        repo=str(repo_path),
        target_url=target_url,
        hypotheses=hypotheses,
        verifications=verifications,
        findings=all_findings,
        meta=meta,
    )


def verify_only(
    hypotheses: list[VulnHypothesis],
    target_url: str,
    *,
    cfg: SecurityConfig | None = None,
    include_target_checks: bool = True,
) -> dict[str, Any]:
    """Verify already-built hypotheses against a target (no code review).

    Used by the DAST stage: the scan orchestrator has already produced the
    hypotheses, the sandbox has booted the application, and this confirms or
    refutes them on the live target.
    """
    cfg = cfg or load_security_config()
    meta: dict[str, Any] = {"status": "skipped", "reason": "verification disabled"}
    if not cfg.verify_enabled:
        return {"verifications": [], "findings": [], "meta": meta}
    try:
        llm = SecurityLlm(cfg)
        verifier = Verifier(target_url, cfg, llm)
        to_verify = list(hypotheses)
        if include_target_checks:
            to_verify.extend(target_level_hypotheses(target_url))
        verifications = verifier.verify(to_verify)
        findings = verifications_to_findings(verifications, to_verify)
        meta = {"status": "ok", **verifier.stats.as_dict()}
        return {"verifications": verifications, "findings": findings, "meta": meta}
    except Exception as exc:  # noqa: BLE001
        logger.exception("security verification failed")
        return {"verifications": [], "findings": [],
                "meta": {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}}


def top_risks(run: SecurityRun, limit: int = 10) -> list[dict[str, Any]]:
    """Confirmed items sorted by risk — used by reports and the UI."""
    by_id = {h.id: h for h in run.hypotheses}
    rows = []
    for v in run.verifications:
        if v.verdict != Verdict.confirmed:
            continue
        h = by_id.get(v.hypothesis_id)
        risk = verification_risk(v, h)
        rows.append({
            "hypothesis_id": v.hypothesis_id,
            "title": h.title if h else v.plugin,
            "class": h.vuln_class.value if h else (v.plugin or ""),
            "cwe": h.cwe if h else None,
            "file": f"{h.file}:{h.line}" if h and h.file else None,
            "url": v.url,
            "severity": v.severity.value,
            "confidence": v.confidence,
            "risk": risk,
            "priority": priority_bucket(risk),
            "evidence": v.evidence,
        })
    return sorted(rows, key=lambda r: -r["risk"])[:limit]
