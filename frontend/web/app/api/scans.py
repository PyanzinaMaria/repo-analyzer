"""Scan submission API: accepts zip / files / folder / repository link."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Form, Request, UploadFile
from fastapi.responses import RedirectResponse

from app.core.config import get_settings
from app.services import intake
from app.services.registry import is_valid_scan_id, scan_status
from app.services.zipguard import ZipGuardError
from app.ui.engine import Form as AuditForm
from app.ui.engine import ValidationError

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("")
def submit_scan(
    request: Request,
    source_kind: Annotated[str, Form()] = "link",
    repo_url: Annotated[str, Form()] = "",
    files: list[UploadFile] | None = None,
):
    settings = get_settings()
    raw = {"source_kind": source_kind, "repo_url": repo_url}
    form = AuditForm(settings)

    uploaded = [f for f in (files or []) if f.filename]
    file_payload = _read_files(uploaded)

    clean, errors = form.validate(raw, files=file_payload)
    if errors:
        return _back_to_form(request, settings, raw, errors)

    try:
        record = intake.accept_submission(
            settings,
            source_kind=clean.get("source_kind", "link"),
            repo_url=clean.get("repo_url"),
            files=file_payload,
        )
    except intake.IntakeError as exc:
        return _back_to_form(request, settings, raw, {"_intake": ValidationError(exc.key)})
    except ZipGuardError as exc:
        return _back_to_form(request, settings, raw, {"_intake": ValidationError(f"zip_codes.{exc.code}")})

    return RedirectResponse(url=f"/scan/{record.id}", status_code=303)


def _read_files(uploaded: list[UploadFile]) -> list[tuple[str, bytes]]:
    payload = []
    for f in uploaded:
        data = f.file.read()
        payload.append((intake.sanitize_name(f.filename), data))
    return payload


def _back_to_form(request: Request, settings, raw: dict, errors: dict) -> RedirectResponse:
    # Re-render the form with errors; keep submitted values where valid.
    from app.ui.views import render_index

    return render_index(request, values=raw, errors=errors)


@router.get("/{scan_id}/status")
def scan_by_id(scan_id: str):
    settings = get_settings()
    if not is_valid_scan_id(scan_id):
        return {"error": "not_found"}
    status = scan_status(settings, scan_id)
    if status is None:
        return {"error": "not_found"}
    return status
