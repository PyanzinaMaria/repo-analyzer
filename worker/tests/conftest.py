"""Worker test fixtures. Everything is offline: the analyzer pipeline is
stubbed at ``Pipeline._analyze`` and only its pydantic models are imported."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from worker.config import WorkerConfig, load_config  # noqa: E402


@pytest.fixture()
def cfg(tmp_path) -> WorkerConfig:
    base = load_config()  # real worker.yaml + frontend contract configs
    return WorkerConfig(
        data_dir=tmp_path / "data",
        poll_interval_seconds=base.poll_interval_seconds,
        enable_ai=False,
        colors=base.colors,
        severity_colors=base.severity_colors,
        doc_disclaimer=base.doc_disclaimer,
        analysis=base.analysis,
        reports=base.reports,
        formats_enabled=base.formats_enabled,
    )


@pytest.fixture()
def make_job(cfg):
    """Write a queue job the way the frontend registry does, including the
    scan record the staleness check requires."""

    def _make(scan_id: str, source: dict, *, with_scan_record: bool = True) -> Path:
        cfg.queue_dir.mkdir(parents=True, exist_ok=True)
        job_path = cfg.queue_dir / f"{scan_id}.json"
        job_path.write_text(
            json.dumps({"scan_id": scan_id, "created_at": "2026-11-18T00:00:00+00:00", "source": source}),
            encoding="utf-8",
        )
        if with_scan_record:
            scan_dir = cfg.uploads_dir / scan_id
            scan_dir.mkdir(parents=True, exist_ok=True)
            (scan_dir / "scan.json").write_text(
                json.dumps({"id": scan_id, "created_at": "", "source": source}), encoding="utf-8"
            )
        return job_path

    return _make


@pytest.fixture()
def scan_result():
    from app.models.finding import CodeInventory, Finding, Severity
    from app.models.report import ScanResult

    return ScanResult(
        scan_id="11111111-1111-1111-1111-111111111111",
        project_id="proj",
        project_name="demo-app",
        enabled_languages=["python"],
        findings=[
            Finding(
                id="f1",
                title="SQL-инъекция",
                description="Строка запроса собирается из пользовательского ввода.",
                severity=Severity.critical,
                cwe="CWE-89",
                file="app/db<x>.py",
                line=42,
                rule_id="B608",
                source="bandit",
                language="python",
                remediation="Использовать параметризованные запросы.",
            ),
            Finding(
                id="f2",
                title="Слабое хеширование",
                description="Используется MD5.",
                severity=Severity.unknown,
                file="app/hash.py",
                line=7,
                source="ai",
                language="python",
            ),
        ],
        inventories=[
            CodeInventory(
                language="python",
                files_count=3,
                modules=["app", "app.db", "app.hash"],
                classes=["Repo", "Hasher"],
                functions=["run", "connect"],
                imports=["os", "sys"],
                dependency_files=["requirements.txt"],
            )
        ],
        summary={
            "total_findings": 2,
            "by_severity": {"critical": 1, "unknown": 1, "info": 0},
            "languages_run": ["python"],
            "high_or_above": 1,
            "ai_findings": 1,
        },
        meta={
            "languages": {"python": {}},
            "ai": {"enabled": True, "status": "skipped", "model": "gpt-4o-mini"},
        },
    )
