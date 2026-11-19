"""SecBench.js (Bhuiyan et al., ICSE 2023): npm vulnerabilities with exploits and sink locations.

Each `<category>/<pkg>_<version>/package.json` has `id` (CVE or ''), `fixCommit` (GitHub commit
URL or 'n/a'), `fixedVersion` and `sink` ('path/in/package.js:line:col'). Only items with a GitHub
fix commit can form a vuln/fixed pair. Every item ships an exploit test -> has_poc.
"""

from __future__ import annotations

import json
from pathlib import Path

from bench.schemas import RawItem, parse_commit_url
from bench.sources._fetch import git_clone_shallow
from bench.config import BenchmarkConfig

NAME = "secbenchjs"
LICENSE = "no license file in repository (research use; cite the ICSE 2023 paper)"
CATEGORY_CWE = {
    "code-injection": ["CWE-94"],
    "command-injection": ["CWE-78"],
    "path-traversal": ["CWE-22"],
    "prototype-pollution": ["CWE-1321"],
    "redos": ["CWE-1333"],
}


def fetch(raw_dir: Path, cfg: BenchmarkConfig, force: bool = False) -> dict:
    sha = git_clone_shallow(cfg.sources.secbenchjs.repo_url, raw_dir / "secbenchjs", force)
    return {"name": NAME, "url": cfg.sources.secbenchjs.repo_url, "version": sha, "license": LICENSE}


def parse_sink(sink: str | None) -> tuple[str, int] | None:
    if not sink or sink == "n/a":
        return None
    parts = sink.rsplit(":", 2)
    if len(parts) == 3 and parts[1].isdigit():
        return parts[0].lstrip("./"), int(parts[1])
    if len(parts) >= 2 and parts[-1].isdigit():
        return ":".join(parts[:-1]).lstrip("./"), int(parts[-1])
    return None


def load(raw_dir: Path, cfg: BenchmarkConfig) -> list[RawItem]:
    root = raw_dir / "secbenchjs"
    items: list[RawItem] = []
    for category, cwe in CATEGORY_CWE.items():
        for pj in sorted((root / category).glob("*/package.json")):
            try:
                d = json.loads(pj.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            parsed = parse_commit_url(str(d.get("fixCommit", "")))
            if not parsed:
                continue
            repo, sha = parsed
            cve = d.get("id") or None
            if cve and not cve.upper().startswith("CVE-"):
                cve = None
            sink = parse_sink(d.get("sink"))
            items.append(RawItem(
                source=NAME, cve=cve.upper() if cve else None, repo_url=repo, fix_commit=sha, cwe=list(cwe),
                language="javascript", has_poc=True,
                extra={"secbenchjs_dir": str(pj.parent.relative_to(root)),
                       "sink": {"file": sink[0], "line": sink[1]} if sink else None,
                       "fixed_version": d.get("fixedVersion")},
            ))
    return items
