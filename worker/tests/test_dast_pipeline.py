from __future__ import annotations

import json

from app.models.finding import Finding, Severity
from app.models.report import ScanResult
from worker.pipeline import Pipeline


def test_dast_result_writes_artifacts(cfg, monkeypatch) -> None:
    """When analysis returns a DAST-bearing ScanResult, the worker emits
    dast_report.* into the frontend contract alongside report/doc HTML."""
    pipeline = Pipeline(cfg)

    fake = ScanResult(
        scan_id="dastscan1",
        project_id="dast-dastscan1",
        project_name="127.0.0.1",
        findings=[
            Finding(
                id="1",
                title="Missing header",
                description="x",
                severity=Severity.medium,
                source="dast-preflight",
                language="python",
            )
        ],
        summary={
            "total_findings": 1,
            "by_severity": {"medium": 1},
            "scan_kind": "sast+dast",
        },
        meta={"dast": {"status": "ok", "target_url": "http://127.0.0.1:8001/"}},
    )

    monkeypatch.setattr(pipeline, "_analyze", lambda scan_id, source, options: fake)

    job = {
        "scan_id": "dastscan1",
        "source": {"kind": "zip"},
        "options": {"methods": ["sast"], "formats": ["md"]},
    }
    (cfg.uploads_dir / "dastscan1" / "repo").mkdir(parents=True)
    pipeline.process(job)

    out = cfg.reports_dir / "dastscan1"
    assert (out / "summary.json").is_file()
    assert (out / "report.html").is_file()
    assert (out / "dast_report.json").is_file()
    assert (out / "dast_report.md").is_file()
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["stages"] == {"analysis": "ok", "report": "ok"}
    assert "dast_report.md" in manifest["artifacts"]
    assert "dast_report.json" in manifest["artifacts"]
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["meta"]["scan_kind"] == "sast+dast"
    assert "timing" in summary
