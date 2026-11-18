"""Per-scan pipeline: queue job in, frontend-contract artifacts out.

Stage reporting goes through ``data/reports/{scan_id}/manifest.json`` only —
the frontend owns the ``intake`` stage, so it never appears in manifests this
worker writes. On failure the failing stage and every stage after it are
marked ``fail``: the scan page keeps polling until all stages are terminal,
so leaving ``report`` pending would poll forever.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from worker.config import ARTIFACTS, WorkerConfig
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
        reports_dir = self.cfg.reports_dir / scan_id
        logger.info("Processing scan %s (source kind=%s)", scan_id, source.get("kind"))

        stages = {"analysis": "running", "report": "pending"}
        write_manifest(reports_dir, stages, [])
        try:
            result = self._analyze(scan_id, source)
        except Exception:
            logger.exception("Analysis failed for scan %s", scan_id)
            write_manifest(reports_dir, {"analysis": "fail", "report": "fail"}, [])
            return

        write_manifest(reports_dir, {"analysis": "ok", "report": "running"}, [])
        try:
            self._produce(reports_dir, result)
        except Exception:
            logger.exception("Report rendering failed for scan %s", scan_id)
            write_manifest(reports_dir, {"analysis": "ok", "report": "fail"}, [])
            return

        artifacts = [name for name in ARTIFACTS if (reports_dir / name).is_file()]
        write_manifest(reports_dir, {"analysis": "ok", "report": "ok"}, artifacts)
        logger.info("Scan %s done: %d findings, artifacts %s", scan_id, len(result.findings), artifacts)

    # ------------------------------------------------------------------

    def _analyze(self, scan_id: str, source: dict[str, Any]):
        """Run the analyzer library. Imports are deferred to here so the
        DATA_DIR env var is in place before the analyzer's cached settings
        are built (get_settings() reads the environment on first call)."""
        os.environ["DATA_DIR"] = str(self.cfg.workspaces_dir)

        kind = source.get("kind")
        if kind == "dast":
            return self._analyze_dast(scan_id, source)

        from app.services.ingest import IngestService
        from app.services.scan import ScanOrchestrator
        from app.services.store import ProjectStore

        store = ProjectStore()
        ingest = IngestService(store=store)
        orchestrator = ScanOrchestrator(store=store)

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

        logger.info("Scan %s: project %s (%s), starting analysis", scan_id, project.id, kind)
        scan = orchestrator.start_scan(project.id, enable_ai=True if self.cfg.enable_ai else None)
        result = store.get_result(project.id, scan.id)
        if result is None:
            raise RuntimeError(f"Analyzer produced no result for scan {scan_id}")
        return result

    def _analyze_dast(self, scan_id: str, source: dict[str, Any]):
        from app.dast import DastOrchestrator
        from app.models.dast import DastScanCreate

        target_url = source.get("target_url") or source.get("url")
        if not target_url:
            raise ValueError("DAST job requires source.target_url")
        options = source.get("options") or {}
        body = DastScanCreate(
            target_url=target_url,
            max_duration_seconds=options.get("max_duration_seconds"),
            follow_redirects=bool(options.get("follow_redirects", True)),
        )
        logger.info("Scan %s: DAST target %s", scan_id, target_url)
        return DastOrchestrator().run_to_result(body, scan_id=scan_id)

    def _produce(self, reports_dir: Path, result) -> None:
        reports_dir.mkdir(parents=True, exist_ok=True)

        from worker.rendering import severity_counts

        scan_kind = (result.summary or {}).get("scan_kind") or (
            (result.meta or {}).get("dast") and "dast"
        ) or "sast"
        summary = {
            "severities": severity_counts(result),
            "meta": {"scan_kind": scan_kind},
        }
        (reports_dir / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (reports_dir / "report.html").write_text(render_report(result, self.cfg), encoding="utf-8")
        (reports_dir / "doc.html").write_text(render_doc(result, self.cfg), encoding="utf-8")

        if scan_kind in {"dast", "sast+dast"} or (result.meta or {}).get("dast"):
            from app.dast.report import write_dast_bundle

            write_dast_bundle(result, reports_dir)
