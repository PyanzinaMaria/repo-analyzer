"""Intake protection against malicious archives and uploaded files.

All limits come from ``config/upload.yaml``. Extraction is streaming and
quota-checked: the guard aborts mid-extract as soon as any limit is exceeded,
instead of trusting the archive's declared metadata.

Error codes are raised as :class:`ZipGuardError` and translated through
i18n (``errors.zip_codes.<code>``).
"""

from __future__ import annotations

import os
import shutil
import stat
import time
import zipfile
from pathlib import Path

from app.core.config import UploadConfig

# Ratio checking is unreliable on tiny entries (a 20-byte header can deflate
# to fewer bytes legitimately), so the ratio rule applies only to entries
# whose compressed size reaches this floor.
RATIO_SAMPLE_BYTES = 512

_PROGRESS_ENTRIES = 64        # entries between timeout checks
_PROGRESS_BYTES = 1 << 20     # copied bytes between timeout checks


class ZipGuardError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: str) -> ZipGuardError:
    return ZipGuardError(code)


def _split_parts(name: str) -> list[str]:
    return [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]


def validate_relative_path(raw_name: str, cfg: UploadConfig) -> list[str]:
    """Validate an archive member path and return its clean parts.

    Shared by zip entries and plain uploaded files.
    """
    name = raw_name.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        _reject_traversal()
    parts = _split_parts(name)
    if not parts:
        _reject_traversal()
    if ".." in parts:
        _reject_traversal()
    lowered = [p.lower() for p in parts]
    if any(seg in cfg.forbidden_segments for seg in lowered):
        raise _reject("forbidden")
    if cfg.deny_hidden and any(p.startswith(".") for p in parts):
        raise _reject("hidden")
    if len(parts) > cfg.max_depth:
        raise _reject("too_deep")
    return parts


def _reject_traversal() -> None:
    raise _reject("traversal")


def check_entry_name(name: str, cfg: UploadConfig) -> None:
    """Extension/manifest whitelist check for a leaf file name."""
    if not cfg.entry_allowed(name):
        raise _reject("extension")


def check_upload_files(sizes: list[tuple[str, int]], cfg: UploadConfig) -> None:
    """Validate plain (non-archive) uploads before writing to disk."""
    if len(sizes) > cfg.max_files:
        raise _reject("too_many_files")
    total = 0
    for name, size in sizes:
        validate_relative_path(name, cfg)
        check_entry_name(name, cfg)
        if size > cfg.max_file_bytes:
            raise _reject("file_too_large")
        total += size
        if total > cfg.max_unpacked_bytes:
            raise _reject("too_large")
    if not sizes:
        raise _reject("too_many_files")


class _Budget:
    """Wall-clock and byte budgets for the extraction loop."""

    def __init__(self, cfg: UploadConfig) -> None:
        self.deadline = time.monotonic() + cfg.timeout_seconds
        self.max_total = cfg.max_unpacked_bytes
        self.total = 0

    def tick_time(self) -> None:
        if time.monotonic() > self.deadline:
            raise _reject("timeout")

    def add(self, n: int, *, tick: bool = False) -> None:
        self.total += n
        if self.total > self.max_total:
            raise _reject("too_large")
        if tick:
            self.tick_time()


def extract_zip(archive: Path, dest: Path, cfg: UploadConfig) -> list[str]:
    """Extract ``archive`` into ``dest`` under quota checks.

    Returns the list of extracted relative paths. Raises :class:`ZipGuardError`
    on any violation; partial output is removed before returning the error.
    """
    dest.mkdir(parents=True, exist_ok=True)
    budget = _Budget(cfg)
    try:
        with zipfile.ZipFile(archive) as zf:
            names = _preflight(zf, cfg, budget)
            for i, info in enumerate(zf.infolist()):
                if info.is_dir():
                    continue
                target = _safe_target(dest, info.filename)
                budget.tick_time()
                _copy_member(zf, info, target, cfg, budget)
                names.append(info.filename.replace("\\", "/"))
                if i % _PROGRESS_ENTRIES == 0:
                    budget.tick_time()
    except ZipGuardError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError) as err:
        shutil.rmtree(dest, ignore_errors=True)
        raise _reject("bad_archive") from err
    return names


def _preflight(zf: zipfile.ZipFile, cfg: UploadConfig, budget: _Budget) -> list[str]:
    """Metadata pass: reject invalid entries before touching the disk."""
    declared_total = 0
    file_count = 0
    for info in zf.infolist():
        if stat.S_ISLNK(info.external_attr >> 16):
            raise _reject("symlink")
        parts = validate_relative_path(info.filename, cfg)
        if info.is_dir():
            continue
        file_count += 1
        if file_count > cfg.max_files:
            raise _reject("too_many_files")
        size = info.file_size
        if size > cfg.max_file_bytes:
            raise _reject("file_too_large")
        declared_total += size
        if declared_total > budget.max_total:
            raise _reject("too_large")
        if info.compress_size >= RATIO_SAMPLE_BYTES and size > info.compress_size * cfg.compression_ratio_max:
            raise _reject("ratio")
        check_entry_name(parts[-1], cfg)
    if file_count == 0:
        raise _reject("too_many_files")
    return []


def _safe_target(dest: Path, member_name: str) -> Path:
    """Join dest and member path defensively, independent of declared parts."""
    clean = member_name.replace("\\", "/").lstrip("/")
    target = (dest / clean).resolve()
    if os.path.commonpath([dest.resolve(), str(target)]) != str(dest.resolve()):
        raise _reject("traversal")
    return target


def _copy_member(
    zf: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path, cfg: UploadConfig, budget: _Budget
) -> None:
    """Stream one member to disk enforcing the declared size and byte budget."""
    target.parent.mkdir(parents=True, exist_ok=True)
    copied = 0
    with zf.open(info) as src, target.open("wb") as out:
        while chunk := src.read(1 << 16):
            copied += len(chunk)
            if copied > cfg.max_file_bytes or copied > info.file_size:
                raise _reject("file_too_large")
            out.write(chunk)
            budget.add(len(chunk), tick=(copied % _PROGRESS_BYTES) < (1 << 16))
    if copied != info.file_size:
        raise _reject("bad_archive")
