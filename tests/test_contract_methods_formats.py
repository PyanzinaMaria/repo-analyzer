"""Contract guards: UI methods/formats must keep gating analysis and report shape.

These tests lock the FE↔worker↔analyzer contract before secaudit packages
are wired in. Failures here mean toggles or report sections broke.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.models.finding import Finding, Severity
from app.models.report import ScanResult
from app.services.scan.orchestrator import ScanOrchestrator
from worker.config import load_config
from worker.pipeline import Pipeline
from worker.rendering import _active_sections, render_report


def test_format_plan_html_pdf_emits_report_and_doc_only():
    pipe = Pipeline(load_config())
    assert pipe._format_plan(["html", "pdf"]) == [
        "report.html",
        "report.pdf",
        "doc.html",
        "doc.pdf",
    ]
    assert all(not n.startswith("dast_report") for n in pipe._format_plan(["md", "html", "pdf", "docx"]))


def test_report_sections_follow_meta_runners_only():
    result = ScanResult(
        scan_id="s1",
        project_id="p1",
        project_name="demo",
        findings=[
            Finding(
                id="1",
                title="bandit hit",
                description="x",
                severity=Severity.high,
                source="bandit",
                language="python",
            ),
            Finding(
                id="2",
                title="ai hit",
                description="y",
                severity=Severity.medium,
                source="ai",
                language="python",
            ),
            Finding(
                id="3",
                title="dast hit",
                description="z",
                severity=Severity.low,
                source="dast-preflight",
                language="python",
            ),
        ],
        summary={"by_severity": {"high": 1, "medium": 1, "low": 1}},
        meta={"runners": ["static", "ai"], "ai": {"enabled": True, "status": "ok"}},
    )
    assert _active_sections(result) == ["sast", "llm"]
    html = render_report(result, load_config())
    assert "SAST — статический анализ" in html
    assert "LLM-агент" in html
    assert "DAST — динамический анализ" not in html


def test_orchestrator_skips_dast_when_dynamic_not_selected(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")

    called = {"dast": False}

    def boom(*_a, **_k):
        called["dast"] = True
        raise AssertionError("DAST must not run")

    monkeypatch.setattr("app.services.scan.dast_merge.merge_dast_via_sandbox", boom)

    store = MagicMock()
    store.reports_dir.return_value = tmp_path / "reports"
    # Bypass full start_scan; exercise _run gating directly.
    orch = ScanOrchestrator(store=store)
    handler = MagicMock()
    handler.id = "python"
    handler.detect.return_value = True
    handler.analyze.return_value = MagicMock(findings=[], inventory=None, meta={})
    orch.registry = MagicMock()
    orch.registry.enabled.return_value = [handler]

    monkeypatch.setattr(
        "app.services.scan.orchestrator.run_ai_analysis",
        lambda *a, **k: ([], {"enabled": False, "status": "skipped"}),
    )
    monkeypatch.setattr(
        "app.services.scan.orchestrator.run_llm_stage",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("LLM must not run")),
    )

    result = orch._run("proj", "scan1", root, "t", enable_ai=False, methods=["static"])
    assert called["dast"] is False
    assert result.meta["runners"] == ["static"]
    assert result.summary["scan_kind"] == "sast"
    handler.analyze.assert_called_once()
    assert "build_context" in handler.analyze.call_args.args[1]


def test_orchestrator_skips_static_when_only_ai(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")

    store = MagicMock()
    store.reports_dir.return_value = tmp_path / "reports"
    orch = ScanOrchestrator(store=store)
    handler = MagicMock()
    handler.id = "python"
    handler.detect.return_value = True
    orch.registry = MagicMock()
    orch.registry.enabled.return_value = [handler]

    monkeypatch.setattr(
        "app.services.scan.orchestrator.run_ai_analysis",
        lambda *a, **k: ([], {"enabled": True, "status": "skipped"}),
    )
    monkeypatch.setattr(
        "app.services.scan.orchestrator.run_llm_stage",
        lambda *a, **k: ({}, {"enabled": False, "status": "skipped", "error": "no key"}),
    )
    monkeypatch.setattr(
        "app.sast.engine.analyze_language",
        lambda *a, **k: __import__("app.sast.engine", fromlist=["LanguageRun"]).LanguageRun(
            language="python", work_dir=tmp_path / "reports" / "secaudit" / "python"
        ),
    )

    result = orch._run("proj", "scan1", root, "t", enable_ai=True, methods=["ai"])
    handler.analyze.assert_not_called()
    assert result.meta["languages"]["_static"]["skipped"] is True
    assert result.meta["runners"] == ["ai"]


def test_worker_maps_form_methods_to_runners():
    pipe = Pipeline(load_config())
    runners, formats = pipe._resolve_options(
        {"methods": ["sast", "dast", "llm_agentic"], "formats": ["html"]}
    )
    assert runners == ["static", "dynamic", "ai"]
    assert formats == ["html"]
