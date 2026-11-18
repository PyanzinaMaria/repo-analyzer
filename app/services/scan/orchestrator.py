from __future__ import annotations

import logging
import uuid
from collections import Counter
from pathlib import Path

from app.ai import run_ai_analysis
from app.ai.config import load_ai_settings
from app.ai.pipeline import run_llm_stage
from app.core import io
from app.core.config import get_settings
from app.core.yaml_configs import in_product_code
from app.languages.registry import LanguageRegistry, build_registry
from app.models.finding import Finding, Severity
from app.models.project import ProjectStatus, ScanInfo, ScanStatus
from app.models.report import ScanResult
from app.sast.engine import LanguageRun
from app.sast.normalize import MergedFinding, rank_sast
from app.services.report.audit import render_markdown as render_audit_markdown
from app.services.report.fstec import render_fstec_draft
from app.services.report.security import render_security_markdown, write_security_json
from app.services.scan.ranking import audit_data, ordered, rank_scan
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

        scan = ScanInfo(
            id=uuid.uuid4().hex,
            project_id=project_id,
            status=ScanStatus.running,
            enabled_languages=[h.id for h in self.registry.enabled()],
        )
        self.store.save_scan(scan)
        self.store.update_status(project_id, ProjectStatus.scanning)

        try:
            reports_dir = self.store.reports_dir(project_id, scan.id)
            result, audit_md = self._run(
                project_id,
                scan.id,
                Path(project.workspace_path),
                project.name,
                enable_ai=enable_ai,
                work_dir=reports_dir / "secaudit",
                repo_url=project.source_ref if project.source_type.value == "github" else None,
            )
            write_security_json(result, reports_dir / "security_report.json")
            render_security_markdown(result, reports_dir / "security_report.md")
            render_fstec_draft(result, reports_dir / "fstec_draft.md")
            (reports_dir / "audit_report.md").write_text(audit_md, encoding="utf-8")

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
        work_dir: Path | None = None,
        repo_url: str | None = None,
    ) -> tuple[ScanResult, str]:
        """Language handlers (SAST + code context) -> LLM triage/discovery -> ranking -> optional file
        review. Returns the result and the Markdown audit document."""
        findings: list[Finding] = []
        inventories = []
        language_meta = {}
        runs: list[LanguageRun] = []
        work_dir = work_dir or self.store.reports_dir(project_id, scan_id) / "secaudit"

        for handler in self.registry.enabled():
            if not handler.detect(root):
                language_meta[handler.id] = {"skipped": True, "reason": "not detected"}
                continue
            analysis = handler.analyze(
                root, {"project_id": project_id, "scan_id": scan_id, "work_dir": str(work_dir)}
            )
            findings.extend(analysis.findings)
            if analysis.inventory:
                inventories.append(analysis.inventory)
            language_meta[handler.id] = analysis.meta
            run = _language_run(analysis.meta.get("secaudit"))
            if run is not None:
                runs.append(run)

        ai_cfg = load_ai_settings()
        llm_results, llm_meta = run_llm_stage(
            ai_cfg, root, runs, get_settings().data_dir.parent, enable_override=enable_ai
        )
        ranking = rank_scan(root, findings, runs, llm_results)
        findings.extend(ranking.new_findings)
        io.write_json(work_dir / "ranking.json", ranking.to_json())

        # meta.ai describes the LLM stage (triage/discovery); the file-review mode reports its own meta
        ai_meta: dict = dict(llm_meta)
        if "review" in ai_cfg.modes:
            ai_findings, ai_meta = run_ai_analysis(
                root,
                findings,
                inventories,
                enable_override=enable_ai,
            )
            findings.extend(ai_findings)
        findings = ordered(findings)

        active = [f for f in findings if not f.extra.get("dismissed")]
        severity_counts = Counter(f.severity.value for f in active)
        summary = {
            "total_findings": len(active),
            "by_severity": dict(severity_counts),
            "languages_run": [h.id for h in self.registry.enabled()],
            "high_or_above": sum(
                1
                for f in active
                if f.severity in {Severity.critical, Severity.high}
            ),
            "ai_findings": sum(1 for f in active if f.source in ("ai", "ai-discovery")),
            "ai_confirmed": sum(1 for f in active if f.extra.get("verdict") == "true_positive"),
            "dismissed_by_ai": sum(1 for f in findings if f.extra.get("dismissed")),
            "ranking": ranking.config,
        }
        audit = audit_data(
            root, project_name, runs, ranking, ai_cfg.model if llm_meta.get("enabled") else None, repo_url
        )
        result = ScanResult(
            scan_id=scan_id,
            project_id=project_id,
            project_name=project_name,
            enabled_languages=[h.id for h in self.registry.enabled()],
            findings=findings,
            inventories=inventories,
            summary=summary,
            meta={
                "languages": language_meta,
                "ai": ai_meta,
                "llm": llm_meta,
                "ranking": ranking.config,
                "attack_surface": {
                    "context": audit.context,
                    "entry_points": dict(audit.entry_kinds.most_common(10)),
                    "sinks_by_cwe": dict(audit.sink_cwes.most_common(10)),
                    "tools": audit.sast,
                },
            },
        )
        return result, render_audit_markdown(audit, top=15, details=5)


def _language_run(meta: dict | None) -> LanguageRun | None:
    """Rebuild the static-stage result a handler reported in LanguageAnalysis.meta['secaudit']."""
    if not meta:
        return None
    run = LanguageRun(language=meta["language"], work_dir=Path(meta["work_dir"]))
    run.tools, run.context, run.loc, run.errors = meta["tools"], meta["context"], meta["loc"], meta["errors"]
    path = run.sast_dir / "merged.jsonl"
    merged = [MergedFinding.model_validate(r) for r in io.read_jsonl(path)] if path.exists() else []
    run.merged = rank_sast([m for m in merged if in_product_code(m.file)])
    return run
