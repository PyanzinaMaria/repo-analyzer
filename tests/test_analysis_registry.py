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
    # The repo settings.yaml enables static + ai + dynamic (manual still off).
    assert enabled_runners() == ("static", "ai", "dynamic")


def test_check_runners_known_vs_unknown():
    check_runners(None)  # legacy path: no restriction
    check_runners(["static", "ai", "dynamic"])
    with pytest.raises(ValueError, match="unknown analysis runner"):
        check_runners(["tarot"])
    with pytest.raises(ValueError, match="disabled in this deployment"):
        check_runners(["manual"])  # known, but not enabled in settings.yaml


def test_scan_endpoint_rejects_disabled_runner(client, tmp_path):
    sample = _sample_repo(tmp_path / "sample_repo")
    project_id = client.post(
        "/api/v1/projects",
        json={"source_type": "local_path", "local_path": str(sample), "name": "runners"},
    ).json()["id"]

    r = client.post(f"/api/v1/projects/{project_id}/scans", json={"methods": ["manual"]})
    assert r.status_code == 400
    assert "disabled in this deployment" in r.json()["detail"]


def test_scan_endpoint_threads_methods(client, tmp_path):
    """methods=[ai] forces the AI override regardless of config; the served
    model comes from the analyzer's own settings (ai.model), not the client."""
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
    assert meta["ai"]["status"] == "skipped"  # no api key in the test env
