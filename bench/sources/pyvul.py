"""PyVul (arXiv 2509.04260, github.com/billquan/PyVul): commit-level Python vulnerability benchmark.

`dataset/commit_level_dataset.out` lists fix-commit URLs (one per line);
`dataset/commits_cwe_map.json` maps commit URL -> CWE. CVE/date are joined from OSV later.
"""

from __future__ import annotations

import json
from pathlib import Path

from bench.schemas import RawItem, parse_commit_url
from bench.sources._fetch import git_clone_shallow
from bench.config import BenchmarkConfig
from app.sast.cwe_map import cwes_from_strings

NAME = "pyvul"
URL = "https://github.com/billquan/PyVul"
LICENSE = "no license file in repository (research use; cite the paper)"


def fetch(raw_dir: Path, cfg: BenchmarkConfig, force: bool = False) -> dict:
    sha = git_clone_shallow(URL, raw_dir / "pyvul", force)
    return {"name": NAME, "url": URL, "version": sha, "license": LICENSE}


def load(raw_dir: Path, cfg: BenchmarkConfig) -> list[RawItem]:
    ds = raw_dir / "pyvul" / "dataset"
    cwe_map_raw = json.loads((ds / "commits_cwe_map.json").read_text(encoding="utf-8"))
    cwe_map = {k.strip().rstrip("/"): v for k, v in cwe_map_raw.items()}
    items: list[RawItem] = []
    seen = set()
    for line in (ds / "commit_level_dataset.out").read_text(encoding="utf-8").splitlines():
        url = line.strip().rstrip("/")
        parsed = parse_commit_url(url)
        if not parsed or parsed in seen:
            continue
        seen.add(parsed)
        cwe = cwe_map.get(url)
        items.append(RawItem(
            source=NAME, repo_url=parsed[0], fix_commit=parsed[1],
            cwe=cwes_from_strings(cwe if isinstance(cwe, list) else [cwe]), language="python",
            extra={"commit_url": url},
        ))
    return items
