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

# Produced by write_dast_bundle when sandbox/DAST actually ran; not part of
# the regular documents×formats render plan.
DAST_ARTIFACTS = ("dast_report.md", "dast_report.json")


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

        # Formats come from reports.yaml (defaults + serveable formats).
        formats = list(options.get("formats")
                       or (self.cfg.reports.get("defaults") or {}).get("formats", []))
        known_formats = {f.get("id") for f in self.cfg.reports.get("formats", [])}
        unknown = [f for f in formats if f not in known_formats]
        if unknown:
            raise ValueError(f"output formats not available: {unknown!r}")
        return runners, formats

    def _format_plan(self, chosen_formats: list[str]) -> list[str]:
        """Artifact names to produce: every document's html plus the chosen
        formats each document supports, honoring the engine switches.
        ``dast_report`` is excluded — it is emitted only when DAST ran."""
        names: list[str] = []
        for doc in self.cfg.reports.get("documents", []):
            if doc.get("id") == "dast_report":
                continue
            for fmt in doc.get("formats", []):
                if fmt != "html" and fmt not in chosen_formats:
                    continue
                if self.cfg.formats_enabled and not self.cfg.formats_enabled.get(fmt, True):
                    continue
                names.append(f"{doc.get('id')}.{fmt}")
        return names

    def _render_html(self, doc_id: str, result) -> str:
        if doc_id == "report":
            return render_report(result, self.cfg)
        if doc_id == "doc":
            return render_doc(result, self.cfg)
        raise ValueError(f"no html renderer for document {doc_id!r}")

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
        # Pass explicit bool — None would fall back to analyzer settings.yaml
        # and run OpenRouter even when worker.enable_ai is false.
        if runners is None:
            enable_arg = self.cfg.enable_ai
        else:
            enable_arg = bool(self.cfg.enable_ai and "ai" in runners)
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

        from worker.formats import HTML_CONVERTERS, render_document_markdown
        from worker.rendering import severity_counts

        _, chosen_formats = self._resolve_options(options)
        plan = self._format_plan(chosen_formats)

        started = time.monotonic()
        html_by_doc: dict[str, str] = {}
        produced: list[str] = []
        for name in plan:
            doc_id, _, fmt = name.rpartition(".")
            target = reports_dir / name
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
        (reports_dir / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        if scan_kind in {"dast", "sast+dast"} or (result.meta or {}).get("dast"):
            from app.dast.report import write_dast_bundle

            write_dast_bundle(result, reports_dir)
            for name in DAST_ARTIFACTS:
                if (reports_dir / name).is_file() and name not in produced:
                    produced.append(name)

        return produced
