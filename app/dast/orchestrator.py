from __future__ import annotations

import logging
import time
import uuid
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from app.dast.config import DastConfig, get_dast_config
from app.dast.preflight import run_preflight
from app.dast.report import write_dast_bundle
from app.dast.ssrf import DastTargetError, validate_target_url
from app.dast.store import DastStore
from app.dast.zap_baseline import run_zap_baseline
from app.languages.registry import LanguageRegistry, build_registry
from app.models.dast import DastScanCreate, DastScanInfo, DastScanStatus
from app.models.finding import Finding, Severity
from app.models.report import ScanResult
from app.services.report.security import render_security_markdown, write_security_json

logger = logging.getLogger(__name__)


class DastOrchestrator:
    def __init__(
        self,
        store: DastStore | None = None,
        registry: LanguageRegistry | None = None,
        cfg: DastConfig | None = None,
    ) -> None:
        self.store = store or DastStore()
        self.registry = registry or build_registry()
        self.cfg = cfg or get_dast_config()

    def start_scan(self, body: DastScanCreate) -> DastScanInfo:
        target_url = str(body.target_url)
        scan = DastScanInfo(
            id=uuid.uuid4().hex,
            status=DastScanStatus.running,
            target_url=target_url,
            enabled_languages=[h.id for h in self.registry.enabled()],
        )
        self.store.save_scan(scan)

        try:
            result = self._run(scan.id, body)
            reports_dir = self.store.reports_dir(scan.id)
            write_security_json(result, reports_dir / "security_report.json")
            render_security_markdown(result, reports_dir / "security_report.md")
            write_dast_bundle(result, reports_dir)

            result_path = str(self.store.save_result(result))
            dast_status = (result.meta.get("dast") or {}).get("status", "ok")
            final = (
                DastScanStatus.skipped
                if dast_status == "skipped"
                else DastScanStatus.completed
            )
            return self.store.mark(
                scan.id,
                final,
                findings_count=len(result.findings),
                result_path=result_path,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("DAST scan failed: %s", scan.id)
            return self.store.mark(scan.id, DastScanStatus.failed, error=str(exc))

    def run_to_result(
        self,
        body: DastScanCreate,
        scan_id: str | None = None,
        *,
        zap_target_url: str | None = None,
        zap_docker_network: str | None = None,
        skip_ssrf: bool = False,
    ) -> ScanResult:
        """Run DAST and return ScanResult without requiring prior API scan row.

        Used by the worker file-contract path where scan_id is already known.
        ``zap_target_url`` / ``zap_docker_network`` let sandbox scans point ZAP
        at a container DNS name on a shared Docker network while preflight uses
        the host-published ``body.target_url``.
        """
        sid = scan_id or uuid.uuid4().hex
        return self._run(
            sid,
            body,
            zap_target_url=zap_target_url,
            zap_docker_network=zap_docker_network,
            skip_ssrf=skip_ssrf,
        )

    def _run(
        self,
        scan_id: str,
        body: DastScanCreate,
        *,
        zap_target_url: str | None = None,
        zap_docker_network: str | None = None,
        skip_ssrf: bool = False,
    ) -> ScanResult:
        started = time.perf_counter()
        target_url = str(body.target_url)
        host = urlparse(target_url).hostname or "target"
        enabled_ids = [h.id for h in self.registry.enabled()]

        if not self.cfg.enabled:
            return self._empty_result(
                scan_id,
                host,
                target_url,
                enabled_ids,
                status="skipped",
                reason="dast.enabled is false",
                duration_ms=0,
            )

        cfg = self.cfg
        if body.max_duration_seconds:
            cfg = DastConfig(
                enabled=cfg.enabled,
                engine=cfg.engine,
                zap_image=cfg.zap_image,
                timeout_seconds=body.max_duration_seconds,
                allowed_schemes=cfg.allowed_schemes,
                allow_private_targets=cfg.allow_private_targets,
                work_dir=cfg.work_dir,
            )

        if not skip_ssrf:
            try:
                validate_target_url(target_url, cfg)
            except DastTargetError as exc:
                raise RuntimeError(str(exc)) from exc

        findings: list[Finding] = []
        preflight_findings, preflight_meta = run_preflight(
            target_url,
            follow_redirects=body.follow_redirects,
            language="http",
        )
        findings.extend(preflight_findings)
        fingerprint = (preflight_meta.get("fingerprint") or {}) if preflight_meta.get("ok") else {}

        if not preflight_meta.get("ok"):
            duration_ms = int((time.perf_counter() - started) * 1000)
            return self._result(
                scan_id=scan_id,
                host=host,
                target_url=target_url,
                enabled_ids=enabled_ids,
                matched_ids=[],
                findings=findings,
                fingerprint=fingerprint,
                preflight=preflight_meta,
                zap={"status": "skipped", "reason": "preflight failed"},
                status="failed",
                duration_ms=duration_ms,
            )

        matched_handlers = []
        for handler in self.registry.enabled():
            try:
                if handler.detect_runtime(target_url, fingerprint):
                    matched_handlers.append(handler)
            except Exception:  # noqa: BLE001
                logger.exception("detect_runtime failed for %s", handler.id)

        matched_ids = [h.id for h in matched_handlers]
        language_tag = matched_ids[0] if len(matched_ids) == 1 else "http"

        # Retag preflight findings to the matched language when unambiguous.
        if language_tag != "http":
            for f in findings:
                if f.source == "dast-preflight":
                    f.language = language_tag

        zap_url = zap_target_url or target_url
        zap_work_dir = None
        if cfg.work_dir:
            # Pre-create through the worker's own mount so the volume
            # subpath exists for the daemon-side --mount below. The ZAP
            # image runs as a non-root user, so the dir must be writable.
            zap_work_dir = Path(cfg.work_dir) / scan_id
            zap_work_dir.mkdir(parents=True, exist_ok=True)
            zap_work_dir.chmod(0o777)
        zap_findings, zap_meta = run_zap_baseline(
            zap_url,
            cfg,
            language=language_tag,
            work_dir=zap_work_dir,
            docker_network=zap_docker_network,
        )
        findings.extend(zap_findings)

        # Active pentest agent on top of the passive baseline: targeted probes
        # (SQLi/XSS/traversal/redirect/command injection) + optional LLM planning.
        pentest_meta: dict[str, object] = {"status": "skipped"}
        if getattr(cfg, "pentest_enabled", True):
            try:
                from app.dast.agent.agent import run_pentest

                pentest_run = run_pentest(
                    target_url,
                    use_llm=getattr(cfg, "pentest_use_llm", True),
                    overrides={
                        "allow_private_targets": cfg.allow_private_targets,
                        "max_steps": getattr(cfg, "pentest_max_steps", 12),
                        "max_seconds": getattr(cfg, "pentest_max_seconds", 120),
                    },
                )
                findings.extend(pentest_run.findings)
                pentest_meta = {"status": "ok", **pentest_run.meta()}
            except Exception as exc:  # noqa: BLE001 - agent must not fail the scan
                logger.exception("pentest agent failed")
                pentest_meta = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}

        language_meta: dict[str, object] = {}
        for handler in matched_handlers:
            try:
                analysis = handler.analyze_dast(
                    target_url,
                    {"scan_id": scan_id, "fingerprint": fingerprint},
                )
                findings.extend(analysis.findings)
                language_meta[handler.id] = analysis.meta
            except Exception as exc:  # noqa: BLE001
                logger.exception("analyze_dast failed for %s", handler.id)
                language_meta[handler.id] = {"error": str(exc)}

        duration_ms = int((time.perf_counter() - started) * 1000)
        status = "ok"
        if zap_meta.get("status") == "failed" and not findings:
            status = "failed"
        elif zap_meta.get("status") == "skipped" and not matched_ids and not findings:
            status = "ok"  # preflight-only still useful

        return self._result(
            scan_id=scan_id,
            host=host,
            target_url=target_url,
            enabled_ids=enabled_ids,
            matched_ids=matched_ids,
            findings=findings,
            fingerprint=fingerprint,
            preflight=preflight_meta,
            zap=zap_meta,
            pentest=pentest_meta,
            status=status,
            duration_ms=duration_ms,
            language_meta=language_meta,
        )

    def _empty_result(
        self,
        scan_id: str,
        host: str,
        target_url: str,
        enabled_ids: list[str],
        *,
        status: str,
        reason: str,
        duration_ms: int,
    ) -> ScanResult:
        return self._result(
            scan_id=scan_id,
            host=host,
            target_url=target_url,
            enabled_ids=enabled_ids,
            matched_ids=[],
            findings=[],
            fingerprint={},
            preflight={"ok": False, "reason": reason},
            zap={"status": "skipped", "reason": reason},
            pentest={"status": "skipped", "reason": reason},
            status=status,
            duration_ms=duration_ms,
        )

    def _result(
        self,
        *,
        scan_id: str,
        host: str,
        target_url: str,
        enabled_ids: list[str],
        matched_ids: list[str],
        findings: list[Finding],
        fingerprint: dict,
        preflight: dict,
        zap: dict,
        pentest: dict | None = None,
        status: str,
        duration_ms: int,
        language_meta: dict | None = None,
    ) -> ScanResult:
        severity_counts = Counter(f.severity.value for f in findings)
        return ScanResult(
            scan_id=scan_id,
            project_id=f"dast-{scan_id}",
            project_name=host,
            enabled_languages=enabled_ids,
            findings=findings,
            inventories=[],
            summary={
                "total_findings": len(findings),
                "by_severity": dict(severity_counts),
                "languages_run": enabled_ids,
                "high_or_above": sum(
                    1
                    for f in findings
                    if f.severity in {Severity.critical, Severity.high}
                ),
                "scan_kind": "dast",
            },
            meta={
                "dast": {
                    "status": status,
                    "target_url": target_url,
                    "fingerprint": fingerprint,
                    "languages_considered": enabled_ids,
                    "languages_matched": matched_ids,
                    "preflight": preflight,
                    "zap": zap,
                    "pentest": pentest or {},
                    "language_meta": language_meta or {},
                    "duration_ms": duration_ms,
                }
            },
        )
