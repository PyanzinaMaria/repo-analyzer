"""Per-scan pipeline: queue job in, frontend-contract artifacts out.

Scan options (methods, formats, model) chosen in the submission form travel
inside the job and are resolved against the frontend contract configs here:
``analysis.yaml`` maps method ids to runner keys and lists selectable models,
``reports.yaml`` lists documents x formats. Unknown or unavailable values
fail the analysis stage fast. Stage reporting goes through
``data/reports/{scan_id}/manifest.json`` only — the frontend owns the
``intake`` stage, so it never appears in manifests this worker writes. On
failure the failing stage and every stage after it are marked ``fail``: the
scan page keeps polling until all stages are terminal, so leaving ``report``
pending would poll forever.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from worker.config import WorkerConfig
from worker.rendering import render_doc, render_report

logger = logging.getLogger(__name__)

STAGE_ORDER = ("analysis", "report")

def write_manifest(reports_dir: Path, stages: dict[str, str], artifacts: list[str]) -> None:
    """Whole-file manifest rewrite. The frontend treats an unparseable
    manifest as absent, so torn reads only ever look like 'pending'."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    payload = {"stages": stages, "artifacts": artifacts}
    (reports_dir / "manifest.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )


class Pipeline:
    def __init__(self, cfg: WorkerConfig) -> None:
        self.cfg = cfg

    def process(self, job: dict[str, Any]) -> None:
        scan_id: str = job["scan_id"]
        source: dict[str, Any] = job["source"]
        options: dict[str, Any] = job.get("options") or {}
        reports_dir = self.cfg.reports_dir / scan_id
        logger.info("Processing scan %s (source kind=%s)", scan_id, source.get("kind"))

        stages = {"analysis": "running", "report": "pending"}
        write_manifest(reports_dir, stages, [])
        started = time.monotonic()
        try:
            result = self._analyze(scan_id, source, options)
        except Exception:
            logger.exception("Analysis failed for scan %s", scan_id)
            write_manifest(reports_dir, {"analysis": "fail", "report": "fail"}, [])
            return
        analysis_seconds = round(time.monotonic() - started, 1)

        write_manifest(reports_dir, {"analysis": "ok", "report": "running"}, [])
        try:
            produced = self._produce(reports_dir, result, options, analysis_seconds)
        except Exception:
            logger.exception("Report rendering failed for scan %s", scan_id)
            write_manifest(reports_dir, {"analysis": "ok", "report": "fail"}, [])
            return

        artifacts = [name for name in produced if (reports_dir / name).is_file()]
        write_manifest(reports_dir, {"analysis": "ok", "report": "ok"}, artifacts)
        logger.info("Scan %s done: %d findings, artifacts %s", scan_id, len(result.findings), artifacts)

    # ------------------------------------------------------------------

    def _resolve_options(self, options: dict[str, Any]) -> tuple[list[str] | None, list[str]]:
        """Job options -> (runner keys, chosen formats). Legacy jobs without
        methods keep the worker/analyzer yaml defaults (None); formats
        default to the inherited ``reports.yaml`` defaults."""
        analysis = self.cfg.analysis

        runners: list[str] | None = None
        methods = options.get("methods")
        if methods:
            catalog = {m.get("id"): m for m in analysis.get("methods", [])}
            runners = []
            for method_id in methods:
                spec = catalog.get(method_id)
                if spec is None or not spec.get("available", True):
                    raise ValueError(f"analysis method not available: {method_id!r}")
                runner = spec.get("runner")
                if runner and runner not in runners:
                    runners.append(runner)

        defaults = (self.cfg.reports.get("defaults") or {}).get("formats", [])
        formats = options.get("formats") or defaults
        fstec = next(
            (doc for doc in self.cfg.reports.get("documents", []) if doc.get("id") == "doc"),
            {},
        )
        allowed = set(fstec.get("formats", []))
        # Older queue entries may still request DOCX or ZIP.
        unknown = [f for f in formats if f not in allowed and f not in {"docx", "zip"}]
        if unknown:
            raise ValueError(f"output formats not available: {unknown!r}")
        return runners, [f for f in formats if f in allowed] or list(defaults)

    def _format_plan(self, chosen_formats: list[str]) -> list[str]:
        """Plan the fixed audit and code formats and the selected FSTEC formats."""
        names: list[str] = []
        for doc in self.cfg.reports.get("documents", []):
            doc_id = doc.get("id")
            if self.cfg.is_ai_doc(doc_id):
                if doc_id not in self.cfg.ai_documents or not self._ai_docs_configured():
                    continue
            elif doc_id not in {"report", "doc"}:
                continue
            for fmt in doc.get("formats", []):
                if doc_id in {"doc", "fstec"}:
                    if fmt not in chosen_formats:
                        continue
                    if not self.cfg.formats_enabled.get(fmt, True):
                        continue
                names.append(f"{doc_id}.{fmt}")
        return names

    def _ai_docs_ready(self) -> bool:
        if not self.cfg.ai_documents_enabled:
            return False
        from app.ai.config import is_ai_enabled

        return is_ai_enabled(True)

    def _ai_docs_configured(self) -> bool:
        """AI documents enabled in config (regardless of API key): the plan
        includes them so a failed generation yields a placeholder doc."""
        return self.cfg.ai_documents_enabled

    def _render_html(self, doc_id: str, result) -> str:
        if doc_id == "report":
            return render_report(result, self.cfg)
        if doc_id == "doc":
            return render_doc(result, self.cfg)
        raise ValueError(f"no html renderer for document {doc_id!r}")

    def _generate_ai_document(self, doc_id: str, result, reports_dir: Path) -> str:
        """Generate one LLM document and persist its attached files
        (docs kit parts, SBOM JSON) under ``reports_dir/docs``."""
        from worker.ai_docs import generate_document, write_files

        workspace_root: Path | None = None
        try:
            from app.services.store import ProjectStore

            workspace = ProjectStore().workspace_dir(result.project_id)
            if workspace.is_dir():
                workspace_root = workspace
            else:
                logger.warning(
                    "Workspace missing for %s; %s payload has no source files",
                    result.project_id, doc_id,
                )
        except Exception:
            logger.warning("Workspace unavailable; %s payload has no source files", doc_id)

        combined, files = generate_document(doc_id, result, self.cfg, workspace_root=workspace_root)
        if files:
            attachments_dir = "docs" if doc_id == "codedocs" else doc_id
            written = write_files(files, reports_dir / attachments_dir)
            logger.info("Wrote %d/%d attached files for %s", len(written), len(files), doc_id)
        return combined

    def _placeholder_ai_document(self, doc_id: str, error: str) -> str:
        """Placeholder markdown when AI generation fails (e.g. no API key):
        keeps the artifact set stable and explains how to enable generation."""
        if doc_id == "fstec":
            title = "Протокол исследований ФСТЭК"
            description = (
                "Протокол исследований по выявлению уязвимостей и "
                "недекларированных возможностей в соответствии с Методикой "
                "ФСТЭК России."
            )
        elif doc_id == "codedocs":
            title = "Документация к коду"
            description = (
                "Автоматически сгенерированная документация по структуре "
                "и логике проекта."
            )
        else:
            title = doc_id
            description = "Документ недоступен."

        return f"""# {title}

> **Внимание:** Этот документ не был сгенерирован ИИ из-за ошибки: {error}

{description}

## Причина

Для генерации данного документа требуется настроенное подключение к LLM.
Проверьте настройки:

- переменная окружения `AI_API_KEY` должна быть установлена;
- `AI_BASE_URL` должен указывать на OpenAI-совместимый эндпоинт;
- в `worker/config/worker.yaml` должен быть `ai_documents.enabled: true`.

После настройки ключа и перезапуска воркера документ будет сгенерирован
автоматически при следующем сканировании.
"""

    def _analyze(self, scan_id: str, source: dict[str, Any], options: dict[str, Any]):
        """Run the analyzer library. Imports are deferred to here so the
        DATA_DIR env var is in place before the analyzer's cached settings
        are built (get_settings() reads the environment on first call)."""
        os.environ["DATA_DIR"] = str(self.cfg.workspaces_dir)

        runners, _ = self._resolve_options(options)

        from app.services.ingest import IngestService
        from app.services.scan import ScanOrchestrator
        from app.services.store import ProjectStore

        store = ProjectStore()
        ingest = IngestService(store=store)
        orchestrator = ScanOrchestrator(store=store)

        kind = source.get("kind")
        if kind == "link":
            # Derive a readable project name from the repo URL; scan_id only
            # as fallback when the URL has no usable last segment.
            url = str(source.get("url") or "").rstrip("/").removesuffix(".git")
            name = url.split("/")[-1] if url.split("/")[-1] else scan_id
            project = ingest.create_from_github(str(source["url"]), name=name)
        elif kind in ("zip", "files"):
            repo_dir = self.cfg.uploads_dir / scan_id / "repo"
            if not repo_dir.is_dir():
                raise FileNotFoundError(f"Upload payload missing: {repo_dir}")
            project = ingest.create_from_local_path(str(repo_dir), name=scan_id)
        else:
            raise ValueError(f"Unsupported source kind: {kind!r}")

        logger.info(
            "Scan %s: project %s (%s), runners=%s, starting analysis",
            scan_id, project.id, kind, runners,
        )
        # Legacy jobs (no methods): honor worker.enable_ai. Form-driven jobs
        # pass the runner list; orchestrator turns AI on iff "ai" is in it.
        if runners is None:
            enable_arg = self.cfg.enable_ai
        else:
            enable_arg = "ai" in runners
        scan = orchestrator.start_scan(project.id, enable_ai=enable_arg, methods=runners)
        result = store.get_result(project.id, scan.id)
        if result is None:
            raise RuntimeError(f"Analyzer produced no result for scan {scan_id}")
        return result

    def _produce(
        self,
        reports_dir: Path,
        result,
        options: dict[str, Any],
        analysis_seconds: float = 0.0,
    ) -> list[str]:
        """Write the artifacts for this scan's document x format plan.
        Returns the artifact names it produced."""
        reports_dir.mkdir(parents=True, exist_ok=True)

        from worker.formats import HTML_CONVERTERS, create_zip_artifact, markdown_to_html, render_document_markdown
        from worker.rendering import severity_counts

        _, chosen_formats = self._resolve_options(options)
        plan = self._format_plan(chosen_formats)

        started = time.monotonic()
        html_by_doc: dict[str, str] = {}
        # LLM documents: one generation per doc id, every format derives
        # from the combined markdown; a failed doc generates a placeholder.
        md_by_doc: dict[str, str] = {}
        docs_status: dict[str, str] = {}
        produced: list[str] = []
        for name in plan:
            doc_id, _, fmt = name.rpartition(".")
            target = reports_dir / name
            if self.cfg.is_ai_doc(doc_id):
                if doc_id not in md_by_doc:
                    try:
                        md_by_doc[doc_id] = self._generate_ai_document(doc_id, result, reports_dir)
                        docs_status[doc_id] = "ok"
                    except Exception as exc:
                        logger.exception("AI document generation failed for %s", doc_id)
                        md_by_doc[doc_id] = self._placeholder_ai_document(doc_id, str(exc))
                        docs_status[doc_id] = "placeholder"
                combined = md_by_doc[doc_id]
                if fmt == "md":
                    target.write_text(combined, encoding="utf-8")
                elif fmt == "html":
                    html = markdown_to_html(combined)
                    html_by_doc[doc_id] = html
                    target.write_text(html, encoding="utf-8")
                elif fmt in HTML_CONVERTERS:
                    html = html_by_doc.get(doc_id) or markdown_to_html(combined)
                    html_by_doc[doc_id] = html
                    target.write_bytes(HTML_CONVERTERS[fmt](html))
                elif fmt == "zip":
                    docs_kit_dir = reports_dir / "docs" if docs_status[doc_id] == "ok" else None
                    create_zip_artifact(docs_kit_dir, target, fallback_markdown=combined)
                else:
                    raise ValueError(f"no handler for format {fmt!r}")
                produced.append(name)
                continue
            if fmt == "html":
                html = self._render_html(doc_id, result)
                html_by_doc[doc_id] = html
                target.write_text(html, encoding="utf-8")
            elif fmt == "md":
                render_document_markdown(doc_id, result, target)
            elif fmt in HTML_CONVERTERS:
                html = html_by_doc.get(doc_id) or self._render_html(doc_id, result)
                target.write_bytes(HTML_CONVERTERS[fmt](html))
            else:
                raise ValueError(f"no handler for format {fmt!r}")
            produced.append(name)
        report_seconds = round(time.monotonic() - started, 1)

        scan_kind = (result.summary or {}).get("scan_kind") or (
            (result.meta or {}).get("dast") and "dast"
        ) or "sast"
        timing = {
            "analysis_seconds": analysis_seconds,
            "report_seconds": report_seconds,
            "total_seconds": round(analysis_seconds + report_seconds, 1),
        }
        summary = {
            "severities": severity_counts(result),
            "timing": timing,
            "meta": {"scan_kind": scan_kind},
        }
        if docs_status:
            summary["documents"] = docs_status
        (reports_dir / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return produced
