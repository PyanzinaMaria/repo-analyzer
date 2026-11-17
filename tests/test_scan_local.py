from __future__ import annotations

from pathlib import Path


def _make_sample_repo(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (root / "app_sample.py").write_text(
        "import pickle\n\ndef load(data):\n    return pickle.loads(data)\n",
        encoding="utf-8",
    )
    return root


def test_local_ingest_and_scan(client, tmp_path):
    sample = _make_sample_repo(tmp_path / "sample_repo")

    create = client.post(
        "/api/v1/projects",
        json={"source_type": "local_path", "local_path": str(sample), "name": "sample"},
    )
    assert create.status_code == 201, create.text
    project = create.json()
    project_id = project["id"]
    assert project["status"] == "ready"

    scan = client.post(f"/api/v1/projects/{project_id}/scans")
    assert scan.status_code == 201, scan.text
    scan_body = scan.json()
    assert scan_body["status"] == "completed"
    scan_id = scan_body["id"]

    result = client.get(f"/api/v1/projects/{project_id}/scans/{scan_id}/result")
    assert result.status_code == 200
    payload = result.json()
    assert payload["summary"]["total_findings"] >= 1

    security_md = client.get(
        f"/api/v1/projects/{project_id}/scans/{scan_id}/reports/security",
        params={"format": "markdown"},
    )
    assert security_md.status_code == 200
    assert "Отчёт по уязвимостям" in security_md.text

    fstec = client.get(
        f"/api/v1/projects/{project_id}/scans/{scan_id}/reports/fstec",
        params={"format": "markdown"},
    )
    assert fstec.status_code == 200
    assert "Черновик документации" in fstec.text
    assert "приказ" in fstec.text.lower() or "ФСТЭК" in fstec.text


def test_language_registry_toggle(tmp_path, monkeypatch):
    from app.core.config import get_settings
    from app.languages.registry import LanguageRegistry
    from app.languages.python.handler import PythonHandler
    from app.languages.javascript.handler import JavaScriptHandler

    cfg = tmp_path / "settings.yaml"
    cfg.write_text("enabled_languages: []\n", encoding="utf-8")
    monkeypatch.setenv("SETTINGS_PATH", str(cfg))
    get_settings.cache_clear()

    registry = LanguageRegistry(
        handlers=[PythonHandler(enabled=False), JavaScriptHandler(enabled=False)]
    )
    assert registry.enabled() == []
