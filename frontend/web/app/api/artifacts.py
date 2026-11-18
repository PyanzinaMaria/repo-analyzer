"""Artifact delivery API: serves ready files produced by other tasks.

The frontend never writes into the reports directory. Artifact names are
restricted to the contract in ``config/reports.yaml`` and scan ids to UUIDs,
which makes path traversal impossible by construction.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.core.config import get_settings
from app.services.registry import available_artifacts, is_valid_scan_id, read_summary

router = APIRouter(prefix="/api/scans/{scan_id}/artifacts", tags=["artifacts"])


def _guard_scan(scan_id: str) -> None:
    settings = get_settings()
    if not is_valid_scan_id(scan_id):
        raise HTTPException(status_code=404, detail="not_found")
    if not (settings.paths.uploads / scan_id).is_dir() and not (settings.paths.reports / scan_id).is_dir():
        raise HTTPException(status_code=404, detail="not_found")


@router.get("")
def list_artifacts(scan_id: str):
    _guard_scan(scan_id)
    settings = get_settings()
    return {
        "artifacts": available_artifacts(settings, scan_id),
        "summary": read_summary(settings, scan_id),
    }


@router.get("/{name}")
def get_artifact(scan_id: str, name: str):
    _guard_scan(scan_id)
    settings = get_settings()
    spec = settings.reports.artifact(name)
    if spec is None:
        raise HTTPException(status_code=404, detail="unknown_artifact")
    path = settings.paths.reports / scan_id / spec.name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="not_ready")
    headers = {}
    if spec.download:
        headers["Content-Disposition"] = f'attachment; filename="{spec.name}"'
    if spec.media_type == "text/html":
        # Sandboxed, script-capable but origin-isolated rendering of
        # producer HTML (which embeds untrusted repository snippets).
        headers["Content-Security-Policy"] = "sandbox allow-scripts"
    return FileResponse(path, media_type=spec.media_type, headers=headers)
