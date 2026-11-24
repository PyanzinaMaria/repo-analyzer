from __future__ import annotations

import subprocess
from pathlib import Path

import httpx


def git_clone_shallow(url: str, dest: Path, force: bool = False) -> str:
    """Shallow clone (or reuse) a dataset repo; returns HEAD sha."""
    if force and dest.exists():
        subprocess.run(["rm", "-rf", str(dest)], check=True)
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "-q", "--depth", "1", url, str(dest)], check=True)
    return subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()


def download(url: str, dest: Path, force: bool = False, headers: dict | None = None) -> Path:
    if dest.exists() and not force:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with httpx.stream("GET", url, follow_redirects=True, timeout=300, headers=headers) as r:
        r.raise_for_status()
        with open(tmp, "wb") as fh:
            for chunk in r.iter_bytes(1 << 20):
                fh.write(chunk)
    tmp.replace(dest)
    return dest
