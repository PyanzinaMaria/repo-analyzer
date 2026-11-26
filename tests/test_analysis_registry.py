"""Analysis runner registry and per-scan methods/model threading."""

from __future__ import annotations

import pytest

from app.analysis.registry import check_runners, enabled_runners
from app.models.project import ScanCreate


def _sample_repo(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / "main.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    return root


def test_scan_create_defaults():
    body = ScanCreate()
    assert body.methods is None
    assert body.enable_ai is None


def test_enabled_runners_come_from_settings_yaml():
    # The repo settings.yaml enables static + ai + dynamic + manual (UI Пентест).
    assert enabled_runners() == ("static", "ai", "dynamic", "manual")


def test_check_runners_known_vs_unknown():
    check_runners(None)  # legacy path: no restriction
    check_runners(["static", "ai", "dynamic", "manual"])
    with pytest.raises(ValueError, match="unknown analysis runner"):
        check_runners(["tarot"])


def test_scan_endpoint_accepts_manual_runner(client, tmp_path, monkeypatch):
    import app.services.scan.orchestrator as orch_mod

    monkeypatch.setattr(
        orch_mod,
        "run_ai_analysis",
        lambda *a, **k: (
            [],
            {
                "enabled": False,
                "status": "skipped",
                "model": None,
                "files_sent": 0,
                "findings_count": 0,
                "error": "test_stub",
            },
        ),
    )
    monkeypatch.setattr(
        "app.services.scan.dast_merge.merge_dast_via_sandbox",
        lambda result, root, **kw: result,
    )
    sample = _sample_repo(tmp_path / "sample_repo")
    project_id = client.post(
        "/api/v1/projects",
        json={"source_type": "local_path", "local_path": str(sample), "name": "runners"},
    ).json()["id"]

    r = client.post(f"/api/v1/projects/{project_id}/scans", json={"methods": ["manual"]})
    assert r.status_code == 201, r.text
    result = client.get(f"/api/v1/projects/{project_id}/scans/{r.json()['id']}/result")
    assert result.status_code == 200
    assert result.json()["meta"]["runners"] == ["manual"]


def test_scan_endpoint_threads_methods(client, tmp_path, monkeypatch):
    """methods=[ai] forces the AI override regardless of config; the served
    model comes from the analyzer's own settings (ai.model), not the client."""
    # Deterministic AI stub: the developer's real .env (AI_API_KEY via
    # env_file) must not leak into endpoint tests.
    import app.services.scan.orchestrator as orch_mod

    monkeypatch.setattr(
        orch_mod, "run_ai_analysis",
        lambda *a, **k: ([], {"enabled": True, "status": "skipped", "model": None,
                              "files_sent": 0, "findings_count": 0, "error": "test_stub"}),
    )
    monkeypatch.setattr(
        orch_mod,
        "run_llm_stage",
        lambda *a, **k: (
            {},
            {"enabled": False, "status": "skipped", "error": "test_stub", "model": None},
        ),
    )
    sample = _sample_repo(tmp_path / "sample_repo2")
    project_id = client.post(
        "/api/v1/projects",
        json={"source_type": "local_path", "local_path": str(sample), "name": "threading"},
    ).json()["id"]

    scan = client.post(
        f"/api/v1/projects/{project_id}/scans",
        json={"methods": ["ai"]},
    )
    assert scan.status_code == 201, scan.text

    result = client.get(f"/api/v1/projects/{project_id}/scans/{scan.json()['id']}/result")
    assert result.status_code == 200
    meta = result.json()["meta"]
    assert meta["runners"] == ["ai"]
    assert meta["ai"]["status"] == "skipped"  # stubbed: no real AI in tests
