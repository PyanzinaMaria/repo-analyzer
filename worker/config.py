"""Worker configuration: worker/config/worker.yaml plus WORKER_* env overrides.

Nothing about the runtime environment is hardcoded; the YAML file is the
single source, environment variables only override it (used by docker-compose).
The producer-side contract — analysis methods/models and documents x formats —
is not duplicated here: it is read from the frontend config tree, the same
files the submission form is built from.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = Path(__file__).resolve().parent / "config" / "worker.yaml"
FRONTEND_CONFIG_DIR = ROOT_DIR / "frontend" / "config"


def _read_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


@dataclass
class WorkerConfig:
    data_dir: Path
    poll_interval_seconds: float = 2.0
    enable_ai: bool = False
    colors: dict[str, str] = field(default_factory=dict)
    severity_colors: dict[str, str] = field(default_factory=dict)
    doc_disclaimer: str = ""
    # frontend/config/analysis.yaml: method catalog (id -> runner/available)
    # and selectable models; frontend/config/reports.yaml: formats, documents
    # and inherited defaults.
    analysis: dict[str, Any] = field(default_factory=dict)
    reports: dict[str, Any] = field(default_factory=dict)
    # Format engines this worker runs (worker.yaml `formats:`); a format not
    # enabled here is skipped for every scan. Absent key = enabled.
    formats_enabled: dict[str, bool] = field(default_factory=dict)

    @property
    def queue_dir(self) -> Path:
        return self.data_dir / "queue"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def workspaces_dir(self) -> Path:
        return self.data_dir / "workspaces"


def load_config(path: Path | None = None) -> WorkerConfig:
    raw: dict[str, Any] = {}
    source = path or CONFIG_PATH
    if source.is_file():
        raw = _read_yaml(source)

    theme = raw.get("theme") or {}
    colors = dict(theme.get("colors") or {})
    severity_colors = dict(theme.get("severity_colors") or {})

    data_dir = Path(os.environ.get("WORKER_DATA_DIR", raw.get("data_dir", "data")))
    if not data_dir.is_absolute():
        data_dir = (ROOT_DIR / data_dir).resolve()

    poll = float(os.environ.get("WORKER_POLL_INTERVAL_SECONDS", raw.get("poll_interval_seconds", 2.0)))
    enable_ai = os.environ.get("WORKER_ENABLE_AI", str(raw.get("enable_ai", False))).strip().lower() in {
        "1",
        "true",
        "yes",
    }

    doc = raw.get("doc") or {}
    formats_enabled = {str(k): bool(v) for k, v in (raw.get("formats") or {}).items()}

    # The frontend contract is required: without it the worker cannot map
    # method ids to runners nor decide which artifacts to produce.
    analysis_path = FRONTEND_CONFIG_DIR / "analysis.yaml"
    reports_path = FRONTEND_CONFIG_DIR / "reports.yaml"
    if not analysis_path.is_file():
        raise FileNotFoundError(f"frontend contract config not found: {analysis_path}")
    if not reports_path.is_file():
        raise FileNotFoundError(f"frontend contract config not found: {reports_path}")

    return WorkerConfig(
        data_dir=data_dir,
        poll_interval_seconds=poll,
        enable_ai=enable_ai,
        colors=colors,
        severity_colors=severity_colors,
        doc_disclaimer=str(doc.get("disclaimer", "")),
        analysis=_read_yaml(analysis_path),
        reports=_read_yaml(reports_path),
        formats_enabled=formats_enabled,
    )
