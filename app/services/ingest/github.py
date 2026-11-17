from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_GITHUB_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


class GitHubIngestError(ValueError):
    pass


def normalize_github_url(url: str) -> str:
    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        # Allow ssh-like or already-normalized https clone URLs
        if raw.endswith(".git") and "github.com" in raw:
            return raw if raw.startswith("http") else f"https://{raw.lstrip('/')}"
        raise GitHubIngestError("Only github.com repositories are supported in MVP")

    path = parsed.path.strip("/")
    parts = path.split("/")
    if len(parts) < 2:
        raise GitHubIngestError("GitHub URL must be owner/repo")
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"https://github.com/{owner}/{repo}.git"


def clone_github_repo(url: str, destination: Path) -> Path:
    settings = get_settings()
    clone_url = normalize_github_url(str(url))
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        clone_url,
        str(destination),
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=settings.git_timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise GitHubIngestError("git is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitHubIngestError("git clone timed out") from exc

    if proc.returncode != 0:
        logger.error("git clone failed: %s", proc.stderr)
        raise GitHubIngestError(proc.stderr.strip() or "git clone failed")
    return destination
