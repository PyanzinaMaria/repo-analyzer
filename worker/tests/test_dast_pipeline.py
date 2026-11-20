from __future__ import annotations

import json

from app.models.finding import Finding, Severity
from app.models.report import ScanResult
from worker.pipeline import Pipeline


def test_dast_result_folds_into_unified_report(cfg, monkeypatch) -> None:
    """DAST findings appear inside report.html sections; no separate
    dast_report.* artifacts are published to the frontend contract."""
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
        meta={
            "runners": ["static", "dynamic"],
            "dast": {"status": "ok", "target_url": "http://127.0.0.1:8001/"},
        },
    )

    monkeypatch.setattr(pipeline, "_analyze", lambda scan_id, source, options: fake)

    job = {
        "scan_id": "dastscan1",
        "source": {"kind": "zip"},
        "options": {"methods": ["sast", "dast"], "formats": ["html", "pdf"]},
    }
    (cfg.uploads_dir / "dastscan1" / "repo").mkdir(parents=True)
    pipeline.process(job)

    out = cfg.reports_dir / "dastscan1"
    assert (out / "summary.json").is_file()
    assert (out / "report.html").is_file()
    assert (out / "report.pdf").is_file()
    assert (out / "doc.html").is_file()
    assert (out / "doc.pdf").is_file()
    assert not (out / "dast_report.json").exists()
    assert not (out / "dast_report.md").exists()

    html = (out / "report.html").read_text(encoding="utf-8")
    assert "DAST — динамический анализ" in html
    assert "Missing header" in html
    assert "http://127.0.0.1:8001/" in html

    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["stages"] == {"analysis": "ok", "report": "ok"}
    assert set(manifest["artifacts"]) == {
        "report.html",
        "report.pdf",
        "doc.html",
        "doc.pdf",
    }
    assert "dast_report.md" not in manifest["artifacts"]
    assert "dast_report.json" not in manifest["artifacts"]
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["meta"]["scan_kind"] == "sast+dast"
    assert "timing" in summary
