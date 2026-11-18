"""Submission intake: normalize zip / multi-file / link submissions.

Writes the accepted payload under ``data/uploads/{scan_id}/``, registers the
scan and publishes the producer job file into the queue directory.
"""

from __future__ import annotations

import re
import urllib.parse

from app.core.config import Settings
from app.services import registry, zipguard


class IntakeError(Exception):
    """Raised with an i18n error key (``errors.*`` or a zip guard code)."""

    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def validate_repo_url(url: str, allowed_hosts: list[str]) -> str:
    url = (url or "").strip()
    if not url.lower().startswith(("http://", "https://")):
        raise IntakeError("errors.bad_url")
    host = urllib.parse.urlparse(url).hostname
    if not host or host.lower() not in [h.lower() for h in allowed_hosts]:
        raise IntakeError("errors.bad_url")
    return url


def accept_submission(
    settings: Settings,
    values: dict,
    files: list[tuple[str, bytes]],
) -> registry.ScanRecord:
    """Persist a validated submission. ``files`` is (relative_name, data).

    ``values`` is the cleaned form: ``source_kind``/``repo_url`` describe the
    source; every other field (methods, formats, model) becomes scan options
    and travels to the producer inside the queue job.
    """
    values = values or {}
    source_kind = values.get("source_kind", "link")
    repo_url = values.get("repo_url")
    # Everything but the source fields is scan options for the producer;
    # upload payloads themselves are not options.
    from app.ui.engine import Form

    form = Form(settings)
    payload_fields = {f.name for f in form.spec.fields if f.type in ("file-multi", "folder")}
    options = {
        k: v for k, v in values.items()
        if k not in ("source_kind", "repo_url") and k not in payload_fields
    }
    _check_options(settings, options)

    if source_kind == "link":
        url = repo_url or ""
        # Host allowlist lives on the form spec; the same list guards intake.
        field = form.field("repo_url")
        url = validate_repo_url(url, field.validators.allowed_hosts or [])
        record = registry.create_scan(settings, {"kind": "link", "url": url}, options=options)
        return record

    if not files:
        raise IntakeError("errors.empty_upload")

    sizes = [(name, len(data)) for name, data in files]
    single_zip = len(files) == 1 and files[0][0].lower().endswith(".zip")
    if single_zip:
        record = registry.create_scan(settings, {"kind": "zip", "file_count": 1}, options=options)
    else:
        record = registry.create_scan(settings, {"kind": "files", "file_count": len(files)}, options=options)

    dest = registry.scan_dir(settings, record.id)
    try:
        if single_zip:
            archive = dest / "_archive.zip"
            archive.write_bytes(files[0][1])
            if archive.stat().st_size > settings.upload.max_upload_bytes:
                raise zipguard.ZipGuardError("too_large")
            zipguard.extract_zip(archive, dest / "repo", settings.upload)
            archive.unlink()
        else:
            zipguard.check_upload_files(sizes, settings.upload)
            for name, data in files:
                parts = zipguard.validate_relative_path(name, settings.upload)
                # Same payload layout as the zip branch: the worker reads
                # uploads/{scan_id}/repo/ for both kinds.
                target = (dest / "repo").joinpath(*parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
    except zipguard.ZipGuardError as exc:
        registry.invalidate(settings, record.id, stage="intake", state="fail", error=exc.code)
        raise IntakeError(f"errors.zip_codes.{exc.code}") from exc
    return record


def _check_options(settings: Settings, options: dict) -> None:
    """Second gate behind the form: direct API posts must not sneak in
    disabled methods or unknown formats."""
    analysis = settings.analysis
    for method_id in options.get("methods") or []:
        if analysis.method(str(method_id)) is None or not analysis.method(str(method_id)).available:
            raise IntakeError("errors.unavailable_choice")
    known_formats = {f.id for f in settings.reports.formats}
    for format_id in options.get("formats") or []:
        if str(format_id) not in known_formats:
            raise IntakeError("errors.unavailable_choice")


def sanitize_name(name: str) -> str:
    """Normalize browser-provided names to forward-slash relative paths."""
    return re.sub(r"^[A-Za-z]:[/\\]", "", name.replace("\\", "/").lstrip("/"))
