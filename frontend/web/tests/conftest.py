"""Shared test fixtures. Every test case gets an isolated data directory."""

from __future__ import annotations

import shutil

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings, reload_settings


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SIRIUS_DATA_DIR", str(tmp_path / "data"))
    reload_settings()
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c, get_settings(), tmp_path / "data"
    monkeypatch.delenv("SIRIUS_DATA_DIR", raising=False)
    reload_settings()


@pytest.fixture()
def demo_scan(client):
    """Copy the demo fixtures into the isolated data dir; returns scan id."""
    _, settings, _ = client
    fixture_dir = settings.root / "fixtures" / "demo-scan"
    for sub in ("uploads", "reports"):
        src = fixture_dir / sub
        dst = getattr(settings.paths, {"uploads": "uploads", "reports": "reports"}[sub])
        dst.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dst, dirs_exist_ok=True)
    return "00000000-0000-0000-0000-000000000001"
