"""Zip guard security tests: bombs, traversal, symlinks, limits."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from app.core.config import get_settings, reload_settings
from app.services import zipguard


def make_zip(path: Path, entries: dict[str, bytes], symlinks: dict[str, str] | None = None) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (0o120777 << 16) | 0o777
            zf.writestr(info, target)


@pytest.fixture()
def cfg():
    reload_settings()
    return get_settings().upload


def _extract(tmp_path, entries, cfg, **overrides):
    workdir = tmp_path / "dest"
    archive = tmp_path / "src.zip"
    make_zip(archive, entries)
    config = cfg.model_copy(update=overrides) if overrides else cfg
    return zipguard.extract_zip(archive, workdir, config)


def test_clean_zip_extracts(tmp_path, cfg):
    names = _extract(tmp_path, {"app/main.py": b"print(1)", "README.md": b"hi"}, cfg)
    assert sorted(names) == ["README.md", "app/main.py"]


def test_clean_zip_extracts_content_intact(tmp_path, cfg):
    """Regression: extracted files must carry their bytes, not just their names."""
    entries = {"app/main.py": b"print('hello')\n", "docs/req.txt": b"Flask==0.12.4"}
    _extract(tmp_path, entries, cfg)
    workdir = tmp_path / "dest"
    for name, data in entries.items():
        assert (workdir / name).read_bytes() == data


def test_traversal_rejected(tmp_path, cfg):
    with pytest.raises(zipguard.ZipGuardError, match="traversal"):
        _extract(tmp_path, {"../evil.py": b"x"}, cfg)


def test_absolute_path_rejected(tmp_path, cfg):
    with pytest.raises(zipguard.ZipGuardError, match="traversal"):
        _extract(tmp_path, {"/etc/passwd": b"x"}, cfg)


def test_drive_letter_rejected(tmp_path, cfg):
    with pytest.raises(zipguard.ZipGuardError, match="traversal"):
        _extract(tmp_path, {"C:/x.py": b"x"}, cfg)


def test_symlink_rejected(tmp_path, cfg):
    archive = tmp_path / "src.zip"
    make_zip(archive, {}, symlinks={"link.py": "/etc/passwd"})
    with pytest.raises(zipguard.ZipGuardError, match="symlink"):
        zipguard.extract_zip(archive, tmp_path / "dest", cfg)


def test_forbidden_segment(tmp_path, cfg):
    with pytest.raises(zipguard.ZipGuardError, match="forbidden"):
        _extract(tmp_path, {".git/config": b"x"}, cfg)


def test_hidden_file(tmp_path, cfg):
    with pytest.raises(zipguard.ZipGuardError, match="hidden"):
        _extract(tmp_path, {".env": b"SECRET=1"}, cfg)


def test_bad_extension(tmp_path, cfg):
    with pytest.raises(zipguard.ZipGuardError, match="extension"):
        _extract(tmp_path, {"malware.exe": b"MZ"}, cfg)


def test_too_deep(tmp_path, cfg):
    deep = "/".join(["a"] * (cfg.max_depth + 1)) + "/x.py"
    with pytest.raises(zipguard.ZipGuardError, match="too_deep"):
        _extract(tmp_path, {deep: b"x"}, cfg)


def test_zip_bomb_ratio(tmp_path, cfg):
    # 5 MB of zeros compress to far below the ratio ceiling.
    with pytest.raises(zipguard.ZipGuardError, match="ratio"):
        _extract(tmp_path, {"bomb.py": b"\0" * (5 * 1024 * 1024)}, cfg)


def test_file_over_size_cap(tmp_path, cfg):
    data = bytes(range(256)) * 2  # incompressible, 512 bytes
    with pytest.raises(zipguard.ZipGuardError, match="file_too_large"):
        _extract(tmp_path, {"big.py": data}, cfg, max_file_bytes=16)


def test_unpacked_total_cap(tmp_path, cfg):
    data = bytes(range(256)) * 2
    entries = {f"f{i}.py": data for i in range(4)}
    with pytest.raises(zipguard.ZipGuardError, match="too_large"):
        _extract(tmp_path, entries, cfg, max_unpacked_bytes=1000)


def test_too_many_files(tmp_path, cfg):
    entries = {f"f{i}.py": b"x" for i in range(5)}
    with pytest.raises(zipguard.ZipGuardError, match="too_many_files"):
        _extract(tmp_path, entries, cfg, max_files=4)


def test_timeout(tmp_path, cfg):
    with pytest.raises(zipguard.ZipGuardError, match="timeout"):
        _extract(tmp_path, {"x.py": b"x"}, cfg, timeout_seconds=0)


def test_bad_archive(tmp_path, cfg):
    archive = tmp_path / "src.zip"
    archive.write_bytes(b"not a zip file at all")
    with pytest.raises(zipguard.ZipGuardError, match="bad_archive"):
        zipguard.extract_zip(archive, tmp_path / "dest", cfg)


def test_empty_archive(tmp_path, cfg):
    archive = tmp_path / "src.zip"
    with zipfile.ZipFile(archive, "w"):
        pass
    with pytest.raises(zipguard.ZipGuardError, match="too_many_files"):
        zipguard.extract_zip(archive, tmp_path / "dest", cfg)


def test_partial_output_removed_on_failure(tmp_path, cfg):
    dest = tmp_path / "dest"
    with pytest.raises(zipguard.ZipGuardError):
        _extract(tmp_path, {"ok.py": b"x", "../bad.py": b"x"}, cfg)
    assert not dest.exists()


def test_manifest_patterns_allowed(tmp_path, cfg):
    names = _extract(tmp_path, {"requirements.txt": b"flask==1.0", "Dockerfile": b"FROM x"}, cfg)
    assert len(names) == 2


def test_check_upload_files(tmp_path, cfg):
    zipguard.check_upload_files([("a.py", 10)], cfg)
    with pytest.raises(zipguard.ZipGuardError, match="extension"):
        zipguard.check_upload_files([("a.exe", 10)], cfg)
    tight = cfg.model_copy(update={"max_unpacked_bytes": 15})
    with pytest.raises(zipguard.ZipGuardError, match="too_large"):
        zipguard.check_upload_files([("a.py", 10), ("b.py", 10)], tight)
    with pytest.raises(zipguard.ZipGuardError):
        zipguard.check_upload_files([], cfg)
