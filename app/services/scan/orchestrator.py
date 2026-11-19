from __future__ import annotations

import logging
import uuid
from collections import Counter
from pathlib import Path

from app.ai import run_ai_analysis
from app.analysis.registry import check_runners
from app.languages.registry import LanguageRegistry, build_registry
from app.models.finding import Finding, Severity
from app.models.project import ProjectStatus, ScanInfo, ScanStatus
from app.models.report import ScanResult
from app.services.report.fstec import render_fstec_draft
from app.services.report.security import render_security_markdown, write_security_json
from app.services.store import ProjectStore

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    def __init__(
        self,
        store: ProjectStore | None = None,
        registry: LanguageRegistry | None = None,
    ) -> None:
        self.store = store or ProjectStore()
        self.registry = registry or build_registry()

    def start_scan(
        self,
        project_id: str,
        *,
        enable_ai: bool | None = None,
        methods: list[str] | None = None,
    ) -> ScanInfo:
        project = self.store.get_project(project_id)
        if project is None:
            raise KeyError(f"Project not found: {project_id}")
        if project.status not in {
            ProjectStatus.ready,
            ProjectStatus.completed,
            ProjectStatus.failed,
        }:
            raise RuntimeError(f"Project is not ready for scan: {project.status}")

        # Fail fast on runner keys this deployment does not know or offer.
        check_runners(methods)

        scan = ScanInfo(
            id=uuid.uuid4().hex,
            project_id=project_id,
            status=ScanStatus.running,
            enabled_languages=[h.id for h in self.registry.enabled()],
        )
        self.store.save_scan(scan)
        self.store.update_status(project_id, ProjectStatus.scanning)

        try:
            result = self._run(
                project_id,
                scan.id,
                Path(project.workspace_path),
                project.name,
                enable_ai=enable_ai,
                methods=methods,
            )
            reports_dir = self.store.reports_dir(project_id, scan.id)
            write_security_json(result, reports_dir / "security_report.json")
            render_security_markdown(result, reports_dir / "security_report.md")
            render_fstec_draft(result, reports_dir / "fstec_draft.md")
            if (result.summary or {}).get("scan_kind") == "sast+dast" or (result.meta or {}).get(
                "dast"
            ):
                from app.dast.report import write_dast_bundle

                write_dast_bundle(result, reports_dir)

            scan.status = ScanStatus.completed
            scan.findings_count = len(result.findings)
            scan.result_path = str(self.store.save_result(result))
            self.store.save_scan(scan)
            self.store.update_status(project_id, ProjectStatus.completed)
            return scan
        except Exception as exc:  # noqa: BLE001
            logger.exception("Scan failed for project %s", project_id)
            scan.status = ScanStatus.failed
            scan.error = str(exc)
            self.store.save_scan(scan)
            self.store.update_status(project_id, ProjectStatus.failed, error=str(exc))
            raise

    def _run(
        self,
        project_id: str,
        scan_id: str,
        root: Path,
        project_name: str,
        *,
        enable_ai: bool | None = None,
        methods: list[str] | None = None,
    ) -> ScanResult:
        findings: list[Finding] = []
        inventories = []
        language_meta = {}

        # Legacy jobs (methods is None) keep the historical default: run SAST.
        run_static = methods is None or "static" in methods
        if run_static:
            for handler in self.registry.enabled():
                if not handler.detect(root):
                    language_meta[handler.id] = {"skipped": True, "reason": "not detected"}
                    continue
                analysis = handler.analyze(root, {"project_id": project_id, "scan_id": scan_id})
                findings.extend(analysis.findings)
                if analysis.inventory:
                    inventories.append(analysis.inventory)
                language_meta[handler.id] = analysis.meta
        else:
            language_meta["_static"] = {"skipped": True, "reason": "static runner not selected"}

        # Explicit runner selection overrides the enable_ai flag; otherwise
        # the legacy flag/config semantics apply unchanged.
        ai_override = enable_ai if methods is None else ("ai" in methods)
        ai_findings, ai_meta = run_ai_analysis(
            root,
            findings,
            inventories,
            enable_override=ai_override,
        )
        findings.extend(ai_findings)

        severity_counts = Counter(f.severity.value for f in findings)
        summary = {
            "total_findings": len(findings),
            "by_severity": dict(severity_counts),
            "languages_run": [h.id for h in self.registry.enabled()],
            "high_or_above": sum(
                1
                for f in findings
                if f.severity in {Severity.critical, Severity.high}
            ),
            "ai_findings": sum(1 for f in findings if f.source == "ai"),
            "scan_kind": "sast",
        }
        meta: dict = {"languages": language_meta, "ai": ai_meta}
        if methods is not None:
            meta["runners"] = list(methods)
        sast_result = ScanResult(
            scan_id=scan_id,
            project_id=project_id,
            project_name=project_name,
            enabled_languages=[h.id for h in self.registry.enabled()],
            findings=findings,
            inventories=inventories,
            summary=summary,
            meta=meta,
        )

        # DAST (sandbox boot + ZAP/preflight) when the client asked for
        # `dynamic`, or on legacy jobs with no method list (previous default).
        if methods is not None and "dynamic" not in methods:
            return sast_result

        from app.services.scan.dast_merge import merge_dast_via_sandbox

        return merge_dast_via_sandbox(sast_result, root, registry=self.registry)
