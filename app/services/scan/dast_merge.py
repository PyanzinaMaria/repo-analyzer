from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Any

from app.dast import DastOrchestrator
from app.models.dast import DastScanCreate
from app.models.finding import Finding, Severity
from app.models.report import ScanResult
from app.languages.registry import LanguageRegistry
from app.sandbox.config import get_sandbox_config
from app.sandbox.runner import SandboxError, sandbox_session

logger = logging.getLogger(__name__)


def merge_dast_via_sandbox(
    sast_result: ScanResult,
    root: Path,
    *,
    registry: LanguageRegistry | None = None,
    run_zap: bool = True,
    run_active_pentest: bool = True,
) -> ScanResult:
    """After SAST, boot sandbox (if possible) and merge DAST/pentest findings.

    Soft-fails: sandbox/DAST problems never raise; they set meta.sandbox /
    meta.dast status to skipped/failed and leave SAST findings intact.

    ``run_zap`` / ``run_active_pentest`` map to UI checkboxes DAST / Пентест.
    """
    findings: list[Finding] = list(sast_result.findings)
    meta: dict[str, Any] = dict(sast_result.meta or {})
    sandbox_cfg = get_sandbox_config()

    if not sandbox_cfg.enabled:
        meta["sandbox"] = {"status": "skipped", "reason": "sandbox.enabled is false"}
        meta["dast"] = {"status": "skipped", "reason": "sandbox disabled"}
        return _with_merged(sast_result, findings, meta, dast_ran=False)

    try:
        with sandbox_session(root, cfg=sandbox_cfg, registry=registry) as session:
            meta["sandbox"] = {
                "status": "ok",
                **session.meta,
                "container": session.container_name,
                "host_url": session.host_url,
                "network_url": session.network_url,
            }
            try:
                dast = DastOrchestrator(registry=registry)
                dast_result = dast.run_to_result(
                    DastScanCreate(target_url=session.host_url),
                    scan_id=sast_result.scan_id,
                    zap_target_url=session.network_url,
                    zap_docker_network=session.network,
                    skip_ssrf=True,
                    run_zap=run_zap,
                    run_active_pentest=run_active_pentest,
                )
                findings.extend(dast_result.findings)
                meta["dast"] = (dast_result.meta or {}).get("dast") or {
                    "status": "ok",
                    "target_url": session.host_url,
                }
            except Exception as exc:  # noqa: BLE001
                logger.exception("DAST after sandbox boot failed")
                meta["dast"] = {"status": "failed", "reason": str(exc)}

            # Verify code-review hypotheses against the booted application.
            # host_url works when the analyzer runs on the host; otherwise retry
            # through the container network URL.
            try:
                raw_hypotheses = meta.get("security_hypotheses") or []
                if raw_hypotheses:
                    from app.security.config import load_security_config
                    from app.security.models import VulnHypothesis
                    from app.security.pipeline import verify_only

                    sec_cfg = load_security_config({"verify_allow_private": True})
                    hypotheses = [VulnHypothesis(**h) for h in raw_hypotheses]
                    verified = verify_only(hypotheses, session.host_url, cfg=sec_cfg)
                    stats = verified.get("meta") or {}
                    if stats.get("status") != "ok" or not stats.get("ok_responses"):
                        verified = verify_only(hypotheses, session.network_url, cfg=sec_cfg)
                    findings.extend(verified.get("findings") or [])
                    meta["security_verify"] = verified.get("meta") or {}
            except Exception as exc:  # noqa: BLE001
                logger.exception("hypothesis verification after sandbox boot failed")
                meta["security_verify"] = {"status": "failed", "error": str(exc)}
    except SandboxError as exc:
        logger.warning("Sandbox boot skipped: %s", exc)
        meta["sandbox"] = {"status": "skipped", "reason": str(exc)}
        meta["dast"] = {"status": "skipped", "reason": f"sandbox: {exc}"}
    except Exception as exc:  # noqa: BLE001
        logger.exception("Sandbox boot failed unexpectedly")
        meta["sandbox"] = {"status": "failed", "reason": str(exc)}
        meta["dast"] = {"status": "skipped", "reason": f"sandbox failed: {exc}"}

    dast_ran = (meta.get("dast") or {}).get("status") == "ok"
    return _with_merged(sast_result, findings, meta, dast_ran=dast_ran)


def _with_merged(
    sast_result: ScanResult,
    findings: list[Finding],
    meta: dict[str, Any],
    *,
    dast_ran: bool,
) -> ScanResult:
    from app.analysis.registry import compose_scan_kind

    severity_counts = Counter(f.severity.value for f in findings)
    summary = dict(sast_result.summary or {})
    runners = meta.get("runners")
    if isinstance(runners, list):
        scan_kind = compose_scan_kind([str(r) for r in runners])
    else:
        # Legacy jobs: sandbox attempt used to mean the combined SAST+DAST path.
        prior = str(summary.get("scan_kind") or "sast")
        if dast_ran or meta.get("sandbox") is not None:
            scan_kind = "sast+dast"
        else:
            scan_kind = prior
    summary.update(
        {
            "total_findings": len(findings),
            "by_severity": dict(severity_counts),
            "high_or_above": sum(
                1 for f in findings if f.severity in {Severity.critical, Severity.high}
            ),
            "scan_kind": scan_kind,
            "dast_findings": sum(
                1
                for f in findings
                if str(f.source).startswith("dast") or f.source == "zap-baseline"
            ),
            "review_findings": sum(
                1 for f in findings if f.source in {"llm-review", "review-agent"}
            ),
            "pentest_findings": sum(1 for f in findings if f.source == "pentest"),
        }
    )

    return sast_result.model_copy(
        update={
            "findings": findings,
            "summary": summary,
            "meta": meta,
        }
    )
