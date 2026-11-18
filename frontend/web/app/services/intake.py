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
    source_kind: str,
    repo_url: str | None,
    files: list[tuple[str, bytes]],
) -> registry.ScanRecord:
    """Persist a validated submission. ``files`` is (relative_name, data)."""
    if source_kind == "link":
        url = repo_url or ""
        # Host allowlist lives on the form spec; the same list guards intake.
        from app.ui.engine import Form

        form = Form(settings)
        field = form.field("repo_url")
        url = validate_repo_url(url, field.validators.allowed_hosts or [])
        record = registry.create_scan(settings, {"kind": "link", "url": url})
        return record

    if not files:
        raise IntakeError("errors.empty_upload")

    sizes = [(name, len(data)) for name, data in files]
    single_zip = len(files) == 1 and files[0][0].lower().endswith(".zip")
    if single_zip:
        record = registry.create_scan(settings, {"kind": "zip", "file_count": 1})
    else:
        record = registry.create_scan(settings, {"kind": "files", "file_count": len(files)})

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
                target = dest.joinpath(*parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
    except zipguard.ZipGuardError as exc:
        registry.invalidate(settings, record.id, stage="intake", state="fail", error=exc.code)
        raise IntakeError(f"errors.zip_codes.{exc.code}") from exc
    return record


def sanitize_name(name: str) -> str:
    """Normalize browser-provided names to forward-slash relative paths."""
    return re.sub(r"^[A-Za-z]:[/\\]", "", name.replace("\\", "/").lstrip("/"))
