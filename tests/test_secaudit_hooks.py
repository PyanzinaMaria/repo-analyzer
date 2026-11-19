"""Smoke checks for secaudit wiring without breaking DAST / methods gates."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from app.languages.python.handler import PythonHandler
from app.services.scan.orchestrator import ScanOrchestrator


def test_python_handler_keeps_dast_hooks():
    h = PythonHandler()
    assert callable(h.detect_runnable)
    assert callable(h.analyze_dast)
    assert callable(h.detect_runtime)


def test_static_stage_soft_skips_missing_tools(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("import os\nos.system(input())\n", encoding="utf-8")

    # Pretend semgrep binary is missing; bandit may still run via python -m.
    from app.sast.runners.base import ToolMissing

    def boom(*_a, **_k):
        raise ToolMissing("semgrep")

    monkeypatch.setattr("app.sast.runners.semgrep.run", boom)

    h = PythonHandler()
    analysis = h.analyze(root, {"work_dir": str(tmp_path / "secaudit"), "build_context": False})
    assert "secaudit" in analysis.meta
    tools = analysis.meta["secaudit"]["tools"]
    # Soft-skip: scan completes; semgrep recorded as not ok if configured.
    assert isinstance(tools, dict)


def test_ai_not_invoked_without_ai_method(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("x=1\n", encoding="utf-8")

    store = MagicMock()
    store.reports_dir.return_value = tmp_path / "reports"
    orch = ScanOrchestrator(store=store)
    handler = MagicMock()
    handler.id = "python"
    handler.detect.return_value = True
    handler.analyze.return_value = MagicMock(findings=[], inventory=None, meta={})
    orch.registry = MagicMock()
    orch.registry.enabled.return_value = [handler]

    calls = {"llm": 0, "review": 0}

    def llm(*_a, **_k):
        calls["llm"] += 1
        return {}, {"enabled": True, "status": "ok"}

    def review(*_a, **_k):
        calls["review"] += 1
        return [], {"enabled": True, "status": "ok"}

    monkeypatch.setattr("app.services.scan.orchestrator.run_llm_stage", llm)
    monkeypatch.setattr("app.services.scan.orchestrator.run_ai_analysis", review)
    monkeypatch.setattr(
        "app.services.scan.dast_merge.merge_dast_via_sandbox",
        lambda result, *_a, **_k: result,
    )

    orch._run("p", "s", root, "t", methods=["static", "dynamic"])
    assert calls["llm"] == 0
    assert calls["review"] == 0
