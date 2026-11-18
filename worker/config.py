"""Worker configuration: worker/config/worker.yaml plus WORKER_* env overrides.

Nothing about the runtime environment is hardcoded; the YAML file is the
single source, environment variables only override it (used by docker-compose).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = Path(__file__).resolve().parent / "config" / "worker.yaml"

# Artifact names this worker produces; must stay inside the frontend contract
# (frontend/config/reports.yaml). PDFs are not produced yet.
ARTIFACTS = ("report.html", "doc.html")


@dataclass
class WorkerConfig:
    data_dir: Path
    poll_interval_seconds: float = 2.0
    enable_ai: bool = False
    colors: dict[str, str] = field(default_factory=dict)
    severity_colors: dict[str, str] = field(default_factory=dict)
    doc_disclaimer: str = ""

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
        raw = yaml.safe_load(source.read_text(encoding="utf-8")) or {}

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
    return WorkerConfig(
        data_dir=data_dir,
        poll_interval_seconds=poll,
        enable_ai=enable_ai,
        colors=colors,
        severity_colors=severity_colors,
        doc_disclaimer=str(doc.get("disclaimer", "")),
    )
