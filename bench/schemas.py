"""Benchmark data models (spec §3.1–3.2, extended with fixed-side ground truth)."""

from __future__ import annotations

import re
from datetime import date
from typing import Literal

from pydantic import BaseModel, Field, field_validator

Language = Literal["python", "javascript", "typescript"]
Split = Literal["dev", "test", "post_cutoff", "extra"]

_GH_RE = re.compile(r"github\.com[/:]([^/\s]+)/([^/\s#?]+)", re.IGNORECASE)
_COMMIT_RE = re.compile(r"github\.com/([^/\s]+)/([^/\s]+)/(?:pull/\d+/)?commits?/([0-9a-f]{7,40})", re.IGNORECASE)


def norm_repo_url(url: str) -> str | None:
    """Canonical https://github.com/owner/repo (no .git, no trailing slash)."""
    m = _GH_RE.search(url or "")
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    repo = re.sub(r"\.git$", "", repo)
    return f"https://github.com/{owner}/{repo}"


def parse_commit_url(url: str) -> tuple[str, str] | None:
    """github commit URL (also PR commit URLs) -> (repo_url, sha)."""
    m = _COMMIT_RE.search(url or "")
    if not m:
        return None
    return f"https://github.com/{m.group(1)}/{re.sub(r'.git$', '', m.group(2))}", m.group(3).lower()


def repo_key(repo_url: str) -> str:
    return repo_url.lower().rstrip("/")


class RawItem(BaseModel):
    source: str
    cve: str | None = None
    ghsa: str | None = None
    repo_url: str
    fix_commit: str
    cwe: list[str] = Field(default_factory=list)
    language: Language
    published: date | None = None
    multi_commit: bool = False
    has_poc: bool = False
    extra: dict = Field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str]:
        return repo_key(self.repo_url), self.fix_commit.lower()


class GTLocation(BaseModel):
    file: str                              # vulnerable-side path
    kind: Literal["fix_hunk", "sink", "vuln_function"]
    start_line: int                        # vulnerable side
    end_line: int
    pure_addition: bool = False            # fix only added lines here; start/end is the anchor line
    function: str | None = None            # enclosing function on vulnerable side (None = module level)
    function_start: int | None = None
    function_end: int | None = None
    fixed_file: str | None = None
    fixed_start_line: int | None = None
    fixed_end_line: int | None = None
    fixed_function: str | None = None
    fixed_function_start: int | None = None
    fixed_function_end: int | None = None


class Quality(BaseModel):
    tangled: bool = False
    multi_commit: bool = False
    manually_checked: bool = False
    label_ok: bool | None = None
    note: str | None = None


class BenchmarkItem(BaseModel):
    id: str
    language: Language
    repo_url: str
    vuln_commit: str
    fix_commit: str
    cve: str | None = None
    ghsa: str | None = None
    cwe: list[str]
    published: date | None = None
    loc: int
    gt_locations: list[GTLocation]
    has_poc: bool = False
    split: Split
    sources: list[str]
    quality: Quality = Quality()
    files_changed: int = 0
    lines_changed: int = 0

    @field_validator("gt_locations")
    @classmethod
    def _non_empty(cls, v):
        if not v:
            raise ValueError("gt_locations must not be empty")
        return v
