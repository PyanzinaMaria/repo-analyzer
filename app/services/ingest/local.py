from __future__ import annotations

import shutil
import zipfile
from pathlib import Path


class LocalIngestError(ValueError):
    pass


def copy_local_path(source: str | Path, destination: Path) -> Path:
    src = Path(source).expanduser().resolve()
    if not src.exists():
        raise LocalIngestError(f"Local path does not exist: {src}")
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, destination, dirs_exist_ok=False)
    elif src.is_file() and src.suffix.lower() == ".zip":
        extract_zip(src, destination)
    else:
        raise LocalIngestError("local_path must be a directory or .zip file")
    return destination


def extract_zip(zip_path: Path, destination: Path) -> Path:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        _safe_extract(zf, destination)
    # If archive contains a single top-level folder, flatten one level for convenience.
    children = [p for p in destination.iterdir() if p.name != "__MACOSX"]
    if len(children) == 1 and children[0].is_dir():
        inner = children[0]
        tmp = destination.parent / f"{destination.name}__flat"
        if tmp.exists():
            shutil.rmtree(tmp)
        shutil.move(str(inner), str(tmp))
        shutil.rmtree(destination)
        shutil.move(str(tmp), str(destination))
    return destination


def _safe_extract(zf: zipfile.ZipFile, destination: Path) -> None:
    dest = destination.resolve()
    for member in zf.infolist():
        member_path = (destination / member.filename).resolve()
        if not str(member_path).startswith(str(dest)):
            raise LocalIngestError(f"Unsafe path in zip: {member.filename}")
    zf.extractall(destination)
