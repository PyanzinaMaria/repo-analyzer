from __future__ import annotations

import json
from pathlib import Path

from app.models.finding import Finding, Severity
from app.models.report import ScanResult
from worker.pipeline import Pipeline


def test_dast_job_writes_artifacts(tmp_path, monkeypatch) -> None:
    data = tmp_path / "data"
    reports = data / "reports"
    (data / "queue").mkdir(parents=True)
    reports.mkdir()

    from worker.config import WorkerConfig

    cfg = WorkerConfig(data_dir=data, colors={}, severity_colors={})
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
            "scan_kind": "dast",
        },
        meta={"dast": {"status": "ok", "target_url": "http://127.0.0.1:8001/"}},
    )

    monkeypatch.setattr(pipeline, "_analyze_dast", lambda scan_id, source: fake)

    job = {
        "scan_id": "dastscan1",
        "source": {"kind": "dast", "target_url": "http://127.0.0.1:8001/"},
    }
    pipeline.process(job)

    out = reports / "dastscan1"
    assert (out / "summary.json").is_file()
    assert (out / "report.html").is_file()
    assert (out / "dast_report.json").is_file()
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["stages"] == {"analysis": "ok", "report": "ok"}
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["meta"]["scan_kind"] == "dast"
