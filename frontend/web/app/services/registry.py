"""Scan registry: one JSON record per scan, stored with the uploaded payload.

The registry is the frontend's only state. Producers never touch it; they
report through ``manifest.json`` in the reports directory, which this module
merges into the status view.
"""

from __future__ import annotations

import json
import shutil
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from app.core.config import Settings

SCAN_FILE = "scan.json"


class ScanRecord(BaseModel):
    id: str
    created_at: str
    source: dict[str, Any]        # {kind: link|files|zip, url?, file_count?}
    options: dict[str, Any] = Field(default_factory=dict)  # {methods?, formats?, model?}
    stages: dict[str, str] = Field(default_factory=lambda: {"intake": "ok"})
    error: str | None = None      # zip guard code when intake failed


def invalidate(settings: Settings, scan_id: str, stage: str, state: str, error: str | None = None) -> None:
    """Mark a scan as failed at a stage and withdraw its producer job."""
    record = load_scan(settings, scan_id)
    if record is not None:
        record.stages[stage] = state
        record.error = error
        persist(settings, record)
    job = queue_job_path(settings, scan_id)
    if job is not None:
        job.unlink(missing_ok=True)


def is_valid_scan_id(scan_id: str) -> bool:
    try:
        uuid.UUID(scan_id)
    except (ValueError, AttributeError):
        return False
    return True


def scan_dir(settings: Settings, scan_id: str) -> Any:
    """Directory for the scan payload; None when the id is not a safe UUID."""
    if not is_valid_scan_id(scan_id):
        return None
    return settings.paths.uploads / scan_id


def create_scan(
    settings: Settings,
    source: dict[str, Any],
    *,
    options: dict[str, Any] | None = None,
) -> ScanRecord:
    scan_id = str(uuid.uuid4())
    record = ScanRecord(
        id=scan_id,
        created_at=datetime.now(UTC).isoformat(),
        source=source,
        options=options or {},
    )
    persist(settings, record)

    job = {
        "scan_id": scan_id,
        "created_at": record.created_at,
        "source": source,
        "options": record.options,
    }
    queue_path = settings.paths.queue / f"{scan_id}.json"
    queue_path.write_text(json.dumps(job, ensure_ascii=False, indent=2), encoding="utf-8")
    return record


def persist(settings: Settings, record: ScanRecord) -> None:
    directory = settings.paths.uploads / record.id
    directory.mkdir(parents=True, exist_ok=True)
    (directory / SCAN_FILE).write_text(
        record.model_dump_json(indent=2), encoding="utf-8"
    )


def load_scan(settings: Settings, scan_id: str) -> ScanRecord | None:
    directory = scan_dir(settings, scan_id)
    if directory is None:
        return None
    path = directory / SCAN_FILE
    if not path.is_file():
        return None
    return ScanRecord.model_validate_json(path.read_text(encoding="utf-8"))


def read_manifest(settings: Settings, scan_id: str) -> dict[str, Any] | None:
    path = settings.paths.reports / scan_id / settings.reports.manifest_filename
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def read_summary(settings: Settings, scan_id: str) -> dict[str, Any] | None:
    path = settings.paths.reports / scan_id / settings.reports.summary_filename
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def available_artifacts(settings: Settings, scan_id: str) -> list[str]:
    """Artifact names declared by the manifest and known to the contract."""
    manifest = read_manifest(settings, scan_id)
    if not manifest:
        return []
    declared = manifest.get("artifacts", [])
    known = {a.name for a in settings.reports.artifacts}
    report_dir = settings.paths.reports / scan_id
    return [name for name in declared if name in known and (report_dir / name).is_file()]


def scan_status(settings: Settings, scan_id: str) -> dict[str, Any] | None:
    """Full status: record + merged stages + available artifacts + summary."""
    record = load_scan(settings, scan_id)
    if record is None:
        return None
    manifest = read_manifest(settings, scan_id)
    manifest_stages: dict[str, str] = (manifest or {}).get("stages", {})
    stages = []
    for stage in settings.reports.stages:
        if stage == "intake":
            state = record.stages.get(stage, "ok")
        else:
            state = manifest_stages.get(stage, "pending")
        stages.append({"name": stage, "state": state})
    return {
        "id": record.id,
        "created_at": record.created_at,
        "source": record.source,
        "options": record.options,
        "stages": stages,
        "artifacts": available_artifacts(settings, scan_id),
        "summary": read_summary(settings, scan_id),
    }


def queue_job_path(settings: Settings, scan_id: str) -> Any:
    if not is_valid_scan_id(scan_id):
        return None
    return settings.paths.queue / f"{scan_id}.json"


def cleanup_expired(settings: Settings) -> int:
    """Delete scan payloads older than retention_days. Returns removed count."""
    cutoff = time.time() - settings.app.retention_days * 86400
    removed = 0
    uploads = settings.paths.uploads
    if not uploads.is_dir():
        return removed
    for directory in uploads.iterdir():
        if directory.is_dir() and directory.stat().st_mtime < cutoff:
            shutil.rmtree(directory, ignore_errors=True)
            removed += 1
    return removed
