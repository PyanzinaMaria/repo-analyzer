"""PatchEval (arXiv 2511.11019, github.com/bytedance/PatchEval), verified subset.

`patcheval/datasets/patcheval_verified.json`: 230 CVEs (Go/JS/Python) with manually disentangled
vulnerable functions (`vul_func`: file, start/end line at the vulnerable commit), patch URLs and a
Docker image with PoC + tests. We take Python and JavaScript items. All verified items have a PoC.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from bench.schemas import RawItem, norm_repo_url, parse_commit_url
from bench.sources._fetch import git_clone_shallow
from bench.config import BenchmarkConfig
from app.sast.cwe_map import cwes_from_strings

NAME = "patcheval"
URL = "https://github.com/bytedance/PatchEval"
LICENSE = "Apache-2.0"
LANG = {"Python": "python", "JavaScript": "javascript", "TypeScript": "typescript"}


def fetch(raw_dir: Path, cfg: BenchmarkConfig, force: bool = False) -> dict:
    sha = git_clone_shallow(URL, raw_dir / "patcheval-repo", force)
    return {"name": NAME, "url": URL, "version": sha, "license": LICENSE,
            "note": "verified subset only (230 CVEs); full 1000-item set not used"}


def _lit(v):
    if isinstance(v, str):
        try:
            return ast.literal_eval(v)
        except (ValueError, SyntaxError):
            return v
    return v


def load(raw_dir: Path, cfg: BenchmarkConfig) -> list[RawItem]:
    path = raw_dir / "patcheval-repo" / "patcheval" / "datasets" / "patcheval_verified.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    items: list[RawItem] = []
    for d in data:
        lang = LANG.get(d.get("programming_language"))
        if not lang:
            continue
        patch_urls = _lit(d.get("patch_url")) or []
        if isinstance(patch_urls, str):
            patch_urls = [patch_urls]
        commits = [c for c in (parse_commit_url(u) for u in patch_urls) if c]
        if not commits:
            continue
        repo = norm_repo_url(d.get("repo", "")) or commits[0][0]
        cwe_info = _lit(d.get("cwe_info")) or {}
        cwes = cwes_from_strings(list(cwe_info.keys()) if isinstance(cwe_info, dict) else [cwe_info])
        vul_funcs = []
        for f in _lit(d.get("vul_func")) or []:
            if isinstance(f, dict) and f.get("file_path"):
                vul_funcs.append({"file": f["file_path"], "start_line": f.get("start_line"),
                                  "end_line": f.get("end_line"), "commit": f.get("commit")})
        # The last listed commit is taken as the fix; multi-commit fixes go to `extra`.
        items.append(RawItem(
            source=NAME, cve=d.get("cve_id"), repo_url=repo, fix_commit=commits[-1][1], cwe=cwes,
            language=lang, has_poc=True, multi_commit=len({c[1] for c in commits}) > 1,
            extra={"vul_funcs": vul_funcs, "all_fix_commits": [c[1] for c in commits]},
        ))
    return items
