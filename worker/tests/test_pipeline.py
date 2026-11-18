"""Pipeline: manifest transitions, contract artifacts, failure semantics."""

from __future__ import annotations

import json

import pytest

from worker.pipeline import Pipeline, write_manifest


@pytest.fixture()
def pipe(cfg, monkeypatch, scan_result):
    p = Pipeline(cfg)
    monkeypatch.setattr(p, "_analyze", lambda scan_id, source, options: scan_result)
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
    # No options -> inherited defaults (md). md applies to the FSTEC doc
    # only; the audit report is always html.
    assert manifest["artifacts"] == ["report.html", "doc.html", "doc.md"]
    for name in ("report.html", "doc.html", "doc.md", "summary.json"):
        assert (reports_dir / name).stat().st_size > 0

    summary = json.loads((reports_dir / "summary.json").read_text(encoding="utf-8"))
    # unknown -> info, zero counts dropped
    assert summary["severities"] == {"critical": 1, "info": 1}
    timing = summary["timing"]
    assert timing["analysis_seconds"] >= 0
    assert timing["report_seconds"] >= 0
    assert timing["total_seconds"] == round(timing["analysis_seconds"] + timing["report_seconds"], 1)


def test_resolve_options_maps_methods_to_runners(cfg):
    pipe = Pipeline(cfg)
    # legacy job: no selection -> yaml defaults
    assert pipe._resolve_options({}) == (None, ["md"])
    runners, formats = pipe._resolve_options(
        {"methods": ["sast", "llm_agentic"], "formats": ["pdf"]}
    )
    assert runners == ["static", "ai"]
    assert formats == ["pdf"]


def test_resolve_options_rejects_unavailable_and_unknown(cfg):
    pipe = Pipeline(cfg)
    with pytest.raises(ValueError, match="not available"):
        pipe._resolve_options({"methods": ["dast"]})  # planned, available: false
    with pytest.raises(ValueError, match="not available"):
        pipe._resolve_options({"methods": ["tarot"]})  # unknown
    with pytest.raises(ValueError, match="formats not available"):
        pipe._resolve_options({"formats": ["rtf"]})


def test_format_plan_intersection(cfg):
    pipe = Pipeline(cfg)
    # html is always produced; chosen formats apply to the FSTEC doc only
    # (the audit report document carries html alone).
    assert pipe._format_plan(["md"]) == ["report.html", "doc.html", "doc.md"]
    assert pipe._format_plan(["md", "pdf", "docx"]) == [
        "report.html",
        "doc.html",
        "doc.md",
        "doc.pdf",
        "doc.docx",
    ]


def test_format_plan_honors_engine_switches(cfg):
    from dataclasses import replace as dc_replace

    disabled_pdf = dc_replace(cfg, formats_enabled={"pdf": False})
    pipe = Pipeline(disabled_pdf)
    assert pipe._format_plan(["md", "pdf"]) == ["report.html", "doc.html", "doc.md"]


def test_chosen_format_without_engine_fails_report_stage(cfg, make_job, scan_result, monkeypatch):
    """A chosen binary format whose dependency is missing must fail the
    report stage loudly, not silently drop the artifact."""
    scan_id = "11111111-1111-1111-1111-111111111111"
    make_job(scan_id, {"kind": "zip"})
    pipe = Pipeline(cfg)
    monkeypatch.setattr(pipe, "_analyze", lambda scan_id, source, options: scan_result)

    def broken_pdf(html):
        raise RuntimeError("no weasyprint")

    monkeypatch.setattr("worker.formats.html_to_pdf", broken_pdf)
    pipe.process({
        "scan_id": scan_id,
        "source": {"kind": "zip"},
        "options": {"formats": ["md", "pdf"]},
    })

    manifest = read_manifest(cfg.reports_dir / scan_id)
    assert manifest["stages"] == {"analysis": "ok", "report": "fail"}


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

    def boom(scan_id, source, options):
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
    monkeypatch.setattr(pipe, "_analyze", lambda scan_id, source, options: scan_result)

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
