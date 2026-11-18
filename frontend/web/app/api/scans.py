"""Scan submission API: accepts zip / files / folder / repository link.

Form fields are read generically from the form spec: adding a field to
``config/forms/audit_form.yaml`` needs no change here. Non-source fields
(methods, formats, model) travel to the producer as scan ``options``.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, UploadFile
from fastapi.responses import RedirectResponse

from app.core.config import get_settings
from app.services import intake
from app.services.registry import is_valid_scan_id, scan_status
from app.services.zipguard import ZipGuardError
from app.ui.engine import Form as AuditForm
from app.ui.engine import ValidationError

router = APIRouter(prefix="/api/scans", tags=["scans"])

_FILE_FIELD_TYPES = {"file-multi", "folder"}


@router.post("")
async def submit_scan(request: Request, files: list[UploadFile] | None = None):
    settings = get_settings()
    form = AuditForm(settings)

    form_data = await request.form()
    raw: dict = {}
    for field in form.spec.fields:
        if field.type in _FILE_FIELD_TYPES:
            continue
        if field.multi:
            raw[field.name] = [v for v in form_data.getlist(field.name) if v]
        else:
            raw[field.name] = str(form_data.get(field.name, ""))

    # Defaults chain: absent/empty choices inherit the configured defaults,
    # so every accepted scan carries an explicit options set.
    for name, default in form.default_values().items():
        if not raw.get(name):
            raw[name] = default

    uploaded = [f for f in (files or []) if f.filename]
    file_payload = _read_files(uploaded)

    clean, errors = form.validate(raw, files=file_payload)
    if errors:
        return _back_to_form(request, settings, raw, errors)

    try:
        record = intake.accept_submission(settings, clean, files=file_payload)
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
