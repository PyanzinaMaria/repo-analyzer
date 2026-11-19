"""Git helpers: shallow partial bare clones per repo, fetch-by-sha, worktrees."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
from pathlib import Path

GIT_ENV = {
    **os.environ,
    "GIT_TERMINAL_PROMPT": "0",          # never prompt for credentials (deleted/private repos)
    "GIT_ASKPASS": "true",
    "GIT_LFS_SKIP_SMUDGE": "1",
}

_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


class GitError(RuntimeError):
    pass


def _lock(path: Path) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(str(path), threading.Lock())


def git(args: list[str], cwd: Path | None = None, git_dir: Path | None = None, timeout: int = 600,
        check: bool = True, text: bool = True) -> subprocess.CompletedProcess:
    cmd = ["git", "-c", "core.quotepath=off", "-c", "advice.detachedHead=false"]
    if git_dir is not None:
        cmd += ["--git-dir", str(git_dir)]
    cmd += args
    try:
        res = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=text,
                             errors="replace" if text else None, timeout=timeout, env=GIT_ENV)
    except subprocess.TimeoutExpired as e:
        raise GitError(f"timeout after {timeout}s: {' '.join(args[:3])}") from e
    if check and res.returncode != 0:
        raise GitError(f"git {' '.join(args[:4])} failed: {(res.stderr or '').strip()[-500:]}")
    return res


def repo_dir(repos_root: Path, repo_url: str) -> Path:
    m = re.search(r"github\.com/([^/]+)/([^/]+)", repo_url)
    name = f"{m.group(1)}__{m.group(2)}" if m else re.sub(r"\W+", "_", repo_url)
    return repos_root / f"{name.lower()}.git"


def ensure_repo(repos_root: Path, repo_url: str) -> Path:
    gd = repo_dir(repos_root, repo_url)
    with _lock(gd):
        if not (gd / "HEAD").exists():
            gd.mkdir(parents=True, exist_ok=True)
            git(["init", "--bare", "-q"], git_dir=gd)
            git(["remote", "add", "origin", repo_url], git_dir=gd)
            for k, v in [("gc.auto", "0"), ("remote.origin.promisor", "true"),
                         ("remote.origin.partialclonefilter", "blob:none"), ("core.bare", "true")]:
                git(["config", k, v], git_dir=gd)
    return gd


def has_commit(gd: Path, sha: str) -> bool:
    return git(["cat-file", "-e", f"{sha}^{{commit}}"], git_dir=gd, check=False).returncode == 0


def fetch_commit(gd: Path, sha: str, timeout: int = 900) -> str:
    """Fetch `sha` with its parents (depth 2, no blobs). Returns the full sha."""
    with _lock(gd):
        if not has_commit(gd, sha) or not has_commit(gd, f"{sha}^"):
            if len(sha) == 40:
                git(["fetch", "-q", "--depth=2", "--filter=blob:none", "origin", sha], git_dir=gd, timeout=timeout)
            else:  # abbreviated sha: GitHub only serves full shas, so fetch history
                git(["fetch", "-q", "--filter=blob:none", "origin"], git_dir=gd, timeout=timeout)
        full = git(["rev-parse", f"{sha}^{{commit}}"], git_dir=gd).stdout.strip()
    return full


def parents(gd: Path, sha: str) -> list[str]:
    out = git(["rev-list", "--parents", "-n", "1", sha], git_dir=gd).stdout.split()
    return out[1:]


def ls_files(gd: Path, sha: str) -> list[str]:
    """Paths in the tree at `sha` (tree objects only; no blobs are downloaded)."""
    out = git(["ls-tree", "-r", "--name-only", "-z", sha], git_dir=gd, timeout=600).stdout
    return [p for p in out.split("\0") if p]


def show_file(gd: Path, sha: str, path: str) -> bytes | None:
    res = git(["show", f"{sha}:{path}"], git_dir=gd, check=False, text=False, timeout=300)
    return res.stdout if res.returncode == 0 else None


def diff_u0(gd: Path, old: str, new: str) -> str:
    return git(["diff", "-U0", "--no-color", "--no-ext-diff", "--find-renames", "--ignore-blank-lines",
                old, new], git_dir=gd, timeout=600).stdout


def is_sparse(dest: Path) -> bool:
    res = git(["config", "--get", "core.sparseCheckout"], cwd=dest, check=False)
    return res.stdout.strip() == "true"


def add_worktree(gd: Path, sha: str, dest: Path, timeout: int = 1800,
                 sparse_patterns: list[str] | None = None) -> None:
    """Detached worktree at `dest` (idempotent). Missing blobs are fetched in one batch.

    With `sparse_patterns` only matching files are checked out (cheap screening). A later call
    without patterns turns an existing sparse worktree into a full one.
    """
    with _lock(gd):
        if dest.exists() and (dest / ".git").exists():
            head = git(["rev-parse", "HEAD"], cwd=dest, check=False).stdout.strip()
            if head == sha:
                if sparse_patterns is None and is_sparse(dest):
                    git(["sparse-checkout", "disable"], cwd=dest, timeout=timeout)
                return
            remove_worktree(gd, dest)
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        git(["worktree", "prune"], git_dir=gd, check=False)
        if sparse_patterns:
            git(["worktree", "add", "--detach", "--force", "--no-checkout", str(dest), sha],
                git_dir=gd, timeout=timeout)
            git(["sparse-checkout", "set", "--no-cone", *sparse_patterns], cwd=dest, timeout=timeout)
            git(["checkout", "-q", "--detach", sha], cwd=dest, timeout=timeout)
        else:
            git(["worktree", "add", "--detach", "--force", str(dest), sha], git_dir=gd, timeout=timeout)


def remove_worktree(gd: Path, dest: Path) -> None:
    git(["worktree", "remove", "--force", str(dest)], git_dir=gd, check=False)
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    git(["worktree", "prune"], git_dir=gd, check=False)
