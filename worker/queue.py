"""Filesystem job queue consumer.

The frontend writes one ``{scan_id}.json`` job per submission into
``data/queue/``. This module polls that directory and claims jobs by
renaming them to ``{scan_id}.claimed`` — the rename is atomic on the same
volume, so a single worker never processes a job twice. The claimed file
is deleted once the pipeline reaches a terminal manifest state, mirroring
how the frontend withdraws failed-intake jobs itself.
"""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CLAIMED_SUFFIX = ".claimed"


def pending_jobs(queue_dir: Path) -> list[Path]:
    """Unclaimed jobs, oldest first (the filename is a UUID, not an order)."""
    if not queue_dir.is_dir():
        return []
    jobs = [p for p in queue_dir.glob("*.json") if p.is_file()]
    return sorted(jobs, key=lambda p: p.stat().st_mtime)


def claimed_jobs(queue_dir: Path) -> list[Path]:
    """Orphaned claims from a previous crash; reprocessed on startup."""
    if not queue_dir.is_dir():
        return []
    found = [p for p in queue_dir.glob(f"*{CLAIMED_SUFFIX}") if p.is_file()]
    return sorted(found, key=lambda p: p.stat().st_mtime)


def parse_job(path: Path) -> dict[str, Any] | None:
    """Return the job payload, or None when the file is not a valid job."""
    try:
        job = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(job, dict):
        return None
    scan_id = job.get("scan_id")
    if not isinstance(scan_id, str) or not _is_uuid(scan_id):
        return None
    if not isinstance(job.get("source"), dict):
        return None
    return job


def claim(job_path: Path) -> Path | None:
    """Atomically rename a job to .claimed; None when the file disappeared."""
    target = job_path.with_suffix(job_path.suffix + CLAIMED_SUFFIX)
    try:
        job_path.rename(target)
    except OSError:
        return None
    return target


def release(claimed_path: Path, *, processed: bool = True) -> None:
    """Remove a claimed job file. Unprocessed invalid jobs are dropped too:
    the frontend never rewrites a job, so keeping it would only loop forever."""
    try:
        claimed_path.unlink(missing_ok=True)
    except OSError:
        logger.warning("Could not remove claimed job %s", claimed_path, exc_info=True)


def is_stale(job: dict[str, Any], uploads_dir: Path) -> bool:
    """True when the frontend no longer knows this scan (retention cleanup
    removed data/uploads/{scan_id}/): the job can never be served, drop it."""
    scan_id = job["scan_id"]
    return not (uploads_dir / scan_id / "scan.json").is_file()


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return True
