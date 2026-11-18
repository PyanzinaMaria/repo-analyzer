from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture()
def tmp_data_dir(tmp_path, monkeypatch):
    data_dir = tmp_path / "workspaces"
    data_dir.mkdir()
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    # API tests exercise the pipeline, not the analyzers: Bandit only (Semgrep/CodeQL are covered by
    # tests/test_fixtures_sast.py and tests/test_secaudit_scan.py, marked `tools`)
    monkeypatch.setenv("SECAUDIT_SAST_TOOLS", "bandit")
    monkeypatch.setenv("AI_ENABLED", "false")
    # never reach a real provider from tests, even if a developer .env holds keys
    monkeypatch.setenv("AI_API_KEY", "")
    monkeypatch.setenv("OPENROUTER_API_KEY", "")
    # reset cached settings/deps
    from app.core.config import get_settings
    from app.api import deps

    get_settings.cache_clear()
    deps.get_store.cache_clear()
    deps.get_ingest_service.cache_clear()
    deps.get_scan_orchestrator.cache_clear()
    return data_dir


@pytest.fixture()
def client(tmp_data_dir):
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
