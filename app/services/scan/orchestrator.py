from __future__ import annotations

import logging
import uuid
from collections import Counter
from pathlib import Path

from app.ai import run_ai_analysis
from app.ai.config import load_ai_settings
from app.ai.pipeline import run_llm_stage
from app.analysis.registry import check_runners
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
            # Service-only audit markdown (not a frontend serveable artifact).
            audit_md = (result.meta or {}).pop("_audit_markdown", None)
            if isinstance(audit_md, str) and audit_md.strip():
                (reports_dir / "audit_report.md").write_text(audit_md, encoding="utf-8")
            if (result.summary or {}).get("scan_kind") == "sast+dast" or (result.meta or {}).get(
                "dast"
            ):
                from app.dast.report import write_dast_bundle

                write_dast_bundle(result, reports_dir)

            scan.status = ScanStatus.completed
            scan.findings_count = len(
                [f for f in result.findings if not (f.extra or {}).get("dismissed")]
            )
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
        language_meta: dict = {}
        runs: list[LanguageRun] = []

        # Legacy jobs (methods is None) keep the historical default: run SAST.
        run_static = methods is None or "static" in methods
        run_ai = methods is None and enable_ai is not False
        if methods is not None:
            run_ai = "ai" in methods

        # Context for triage/discovery: static or AI-only (not pure DAST).
        want_context = run_static or run_ai

        # Service artifacts for SARIF/context stay under the scan reports dir;
        # they are NOT published as frontend serveable artifacts.
        work_dir = self.store.reports_dir(project_id, scan_id) / "secaudit"

        if run_static:
            for handler in self.registry.enabled():
                if not handler.detect(root):
                    language_meta[handler.id] = {"skipped": True, "reason": "not detected"}
                    continue
                analysis = handler.analyze(
                    root,
                    {
                        "project_id": project_id,
                        "scan_id": scan_id,
                        "work_dir": str(work_dir),
                        "build_context": want_context,
                    },
                )
                findings.extend(analysis.findings)
                if analysis.inventory:
                    inventories.append(analysis.inventory)
                language_meta[handler.id] = analysis.meta
                run = _language_run((analysis.meta or {}).get("secaudit"))
                if run is not None:
                    runs.append(run)
        else:
            language_meta["_static"] = {"skipped": True, "reason": "static runner not selected"}
            # AI-only: still build context via static engine (no SAST tools) when possible.
            if want_context:
                from app.sast.engine import analyze_language

                for handler in self.registry.enabled():
                    if not handler.detect(root):
                        continue
                    try:
                        lang = handler.id
                        run = analyze_language(
                            root,
                            lang,
                            work_dir / lang,
                            tools=[],
                            build_context=True,
                        )
                        language_meta[lang] = {
                            "scanners": [],
                            "secaudit": run.meta(),
                            "context_only": True,
                        }
                        runs.append(run)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("context-only build failed for %s: %s", handler.id, exc)

        ai_cfg = load_ai_settings()
        llm_results: dict = {}
        llm_meta: dict = {"enabled": False, "status": "skipped", "error": "ai runner not selected"}
        review_meta: dict = {"enabled": False, "status": "skipped"}

        if run_ai:
            # Explicit runner selection overrides the enable_ai flag; otherwise
            # the legacy flag/config semantics apply unchanged.
            ai_override = True if methods is not None else enable_ai

            # 1) triage/discovery (gated; needs context when available)
            llm_results, llm_meta = run_llm_stage(
                ai_cfg,
                root,
                runs,
                get_settings().data_dir.parent,
                enable_override=ai_override,
            )

            # 2) file review when configured (safe default mode)
            if "review" in ai_cfg.modes or not any(
                m in ai_cfg.modes for m in ("triage", "discovery")
            ):
                ai_findings, review_meta = run_ai_analysis(
                    root,
                    findings,
                    inventories,
                    enable_override=ai_override,
                )
                findings.extend(ai_findings)
            else:
                review_meta = {
                    "enabled": False,
                    "status": "skipped",
                    "error": "review mode not in ai.modes",
                    "model": ai_cfg.model,
                }
        else:
            # Ensure no OpenRouter/triage calls when AI is not selected.
            review_meta = {
                "enabled": False,
                "status": "skipped",
                "error": "ai runner not selected",
            }

        ranking = rank_scan(root, findings, runs, llm_results if run_ai else None)
        findings.extend(ranking.new_findings)
        try:
            work_dir.mkdir(parents=True, exist_ok=True)
            io.write_json(work_dir / "ranking.json", ranking.to_json())
        except OSError as exc:
            logger.warning("could not write ranking.json: %s", exc)

        findings = ordered(findings)
        active = [f for f in findings if not (f.extra or {}).get("dismissed")]

        severity_counts = Counter(f.severity.value for f in active)
        ai_meta = {
            "enabled": bool(run_ai and (llm_meta.get("enabled") or review_meta.get("enabled"))),
            "status": llm_meta.get("status") or review_meta.get("status") or "skipped",
            "model": llm_meta.get("model") or review_meta.get("model") or ai_cfg.model,
            "review": review_meta,
            "llm": llm_meta,
            "modes": list(ai_cfg.modes) if run_ai else [],
            "error": None
            if run_ai
            else (review_meta.get("error") or llm_meta.get("error")),
        }
        if run_ai and llm_meta.get("error") and review_meta.get("status") == "skipped":
            ai_meta["error"] = llm_meta.get("error")
        elif run_ai and review_meta.get("error") and not llm_meta.get("enabled"):
            ai_meta["error"] = review_meta.get("error")

        has_ai = "ai" in (methods or []) if methods is not None else bool(run_ai)
        has_dast = methods is None or "dynamic" in (methods or [])
        if has_dast:
            scan_kind = "sast+dast"
        elif has_ai:
            scan_kind = "sast_ai"
        else:
            scan_kind = "sast"
        summary = {
            "total_findings": len(active),
            "by_severity": dict(severity_counts),
            "languages_run": [h.id for h in self.registry.enabled()],
            "high_or_above": sum(
                1 for f in active if f.severity in {Severity.critical, Severity.high}
            ),
            "ai_findings": sum(
                1 for f in active if (f.source or "").startswith("ai")
            ),
            "ai_confirmed": sum(
                1 for f in active if (f.extra or {}).get("verdict") == "true_positive"
            ),
            "dismissed_by_ai": sum(
                1 for f in findings if (f.extra or {}).get("dismissed")
            ),
            "ranking": ranking.config,
            "scan_kind": scan_kind,
        }

        audit = audit_data(
            root,
            project_name,
            runs,
            ranking,
            ai_cfg.model if llm_meta.get("enabled") else None,
            None,
        )
        meta: dict = {
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
            # Consumed by start_scan then removed before persist.
            "_audit_markdown": render_audit_markdown(audit, top=15, details=5),
        }
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


def _language_run(meta: dict | None) -> LanguageRun | None:
    """Rebuild the static-stage result a handler reported in LanguageAnalysis.meta['secaudit']."""
    if not meta:
        return None
    run = LanguageRun(language=meta["language"], work_dir=Path(meta["work_dir"]))
    run.tools = meta.get("tools") or {}
    run.context = meta.get("context") or {}
    run.loc = int(meta.get("loc") or 0)
    run.errors = list(meta.get("errors") or [])
    path = run.sast_dir / "merged.jsonl"
    if path.exists():
        merged = [MergedFinding.model_validate(r) for r in io.read_jsonl(path)]
        run.merged = rank_sast([m for m in merged if in_product_code(m.file)])
    return run
