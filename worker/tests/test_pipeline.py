"""Pipeline: manifest transitions, contract artifacts, failure semantics."""

from __future__ import annotations

import json

import pytest

from worker.pipeline import Pipeline, write_manifest


@pytest.fixture()
def pipe(cfg, monkeypatch, scan_result):
    p = Pipeline(cfg)
    monkeypatch.setattr(p, "_analyze", lambda scan_id, source: scan_result)
    return p


def read_manifest(reports_dir):
    return json.loads((reports_dir / "manifest.json").read_text(encoding="utf-8"))


def test_write_manifest_creates_dir_and_payload(tmp_path):
    reports_dir = tmp_path / "deep" / "nested"
    write_manifest(reports_dir, {"analysis": "running"}, ["report.html"])
    assert read_manifest(reports_dir) == {"stages": {"analysis": "running"}, "artifacts": ["report.html"]}


def test_happy_path_produces_contract_artifacts(cfg, make_job, pipe):
    scan_id = "11111111-1111-1111-1111-111111111111"
    make_job(scan_id, {"kind": "zip"})
    pipe.process({"scan_id": scan_id, "source": {"kind": "zip"}})

    reports_dir = cfg.reports_dir / scan_id
    manifest = read_manifest(reports_dir)
    assert manifest["stages"] == {"analysis": "ok", "report": "ok"}
    assert manifest["artifacts"] == ["report.html", "doc.html"]
    for name in ("report.html", "doc.html", "summary.json"):
        assert (reports_dir / name).stat().st_size > 0

    summary = json.loads((reports_dir / "summary.json").read_text(encoding="utf-8"))
    # unknown -> info, zero counts dropped
    assert summary == {"severities": {"critical": 1, "info": 1}}


def test_report_html_escapes_finding_fields(cfg, pipe, scan_result):
    scan_id = "11111111-1111-1111-1111-111111111111"
    pipe.process({"scan_id": scan_id, "source": {"kind": "zip"}})
    html = (cfg.reports_dir / scan_id / "report.html").read_text(encoding="utf-8")

    assert "app/db&lt;x&gt;.py" in html
    assert "<x>" not in html
    assert "SQL-инъекция" in html
    assert "Использовать параметризованные запросы." in html
    assert 'class="donut"' in html


def test_doc_html_contains_protocol_and_disclaimer(cfg, pipe):
    scan_id = "11111111-1111-1111-1111-111111111111"
    pipe.process({"scan_id": scan_id, "source": {"kind": "zip"}})
    html = (cfg.reports_dir / scan_id / "doc.html").read_text(encoding="utf-8")

    assert "ФСТЭК России" in html
    assert cfg.doc_disclaimer[:30] in html
    assert "app/db&lt;x&gt;.py" in html
    assert "app, app.db, app.hash" in html


def test_analysis_failure_fails_all_producer_stages(cfg, make_job, monkeypatch):
    """The failing stage and every stage after it must reach a terminal state,
    otherwise the scan page polls forever."""
    scan_id = "11111111-1111-1111-1111-111111111111"
    make_job(scan_id, {"kind": "link", "url": "https://github.com/o/r"})
    pipe = Pipeline(cfg)

    def boom(scan_id, source):
        raise RuntimeError("clone failed")

    monkeypatch.setattr(pipe, "_analyze", boom)
    pipe.process({"scan_id": scan_id, "source": {"kind": "link"}})

    manifest = read_manifest(cfg.reports_dir / scan_id)
    assert manifest["stages"] == {"analysis": "fail", "report": "fail"}
    assert manifest["artifacts"] == []
    assert not (cfg.reports_dir / scan_id / "summary.json").exists()


def test_produce_failure_fails_only_report_stage(cfg, make_job, scan_result, monkeypatch):
    scan_id = "11111111-1111-1111-1111-111111111111"
    make_job(scan_id, {"kind": "zip"})
    pipe = Pipeline(cfg)
    monkeypatch.setattr(pipe, "_analyze", lambda scan_id, source: scan_result)

    def broken_render(result, cfg):
        raise RuntimeError("template error")

    monkeypatch.setattr("worker.pipeline.render_report", broken_render)
    pipe.process({"scan_id": scan_id, "source": {"kind": "zip"}})

    manifest = read_manifest(cfg.reports_dir / scan_id)
    assert manifest["stages"] == {"analysis": "ok", "report": "fail"}


def test_missing_upload_payload_fails_analysis(cfg, make_job):
    scan_id = "11111111-1111-1111-1111-111111111111"
    make_job(scan_id, {"kind": "zip"}, with_scan_record=True)
    # no data/uploads/{scan_id}/repo/ directory on disk
    pipe = Pipeline(cfg)
    pipe.process({"scan_id": scan_id, "source": {"kind": "zip"}})

    manifest = read_manifest(cfg.reports_dir / scan_id)
    assert manifest["stages"] == {"analysis": "fail", "report": "fail"}
