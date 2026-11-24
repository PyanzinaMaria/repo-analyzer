"""External scanner benchmarks as ready-made corpora: OWASP BenchmarkJava/Python, SecLens, RealVuln.

`build` writes benchmark.jsonl into the current data dir and materializes one shared snapshot
worktree per unique (repo, commit) under snapshots/_groups/. `scan` runs the per-tool pipeline
once per group and attributes findings to every item of the group by file copy, so rank and
eval below stay unchanged. OWASP items are per CWE category (GT = whole TRUE-labeled files,
no fixed side -> Recall@k only), SecLens items are CVE pairs (vulnerable + post-patch commit),
RealVuln items are pinned pre-patch repos (hand-labeled findings, no fixed side).
"""

from __future__ import annotations

import json
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path

import httpx
from pydantic import BaseModel

from app.core import io
from app.core.runlog import RunSummary, log
from app.core.yaml_configs import CONFIG_DIR, Language, _load
from bench import git_utils as g
from bench.build import count_loc
from bench.config import Paths, load_benchmark_config
from bench.schemas import BenchmarkItem, GTLocation, Quality
from bench.sources._fetch import download, git_clone_shallow

SUPPORTED = {"python": "python", "javascript": "javascript", "typescript": "typescript",
             "java": "java", "c#": "csharp", "csharp": "csharp", "jvm": "java"}


class OwaspSpec(BaseModel):
    repo: str
    ref: str                  # pinned commit (releases are stale relative to expectedresults-*.csv)
    csv: str
    testcode: str
    extension: str
    language: Language


class SecLensSpec(BaseModel):
    dataset: str = "enginesec/SecLens"
    quota: int | None = None


class RealVulnSpec(BaseModel):
    labels_repo: str = "https://github.com/kolega-ai/Real-Vuln-Benchmark"
    # limit accepted repos: either per-language {python: 10, java: 5} or one int for all
    quota_per_language: dict[str, int] | int | None = None


def load_config(path: Path | str = CONFIG_DIR / "external.yaml") -> "ExternalConfig":
    return _load(path, ExternalConfig)


class ExternalConfig(BaseModel):
    owasp_java: OwaspSpec
    owasp_python: OwaspSpec
    seclens: SecLensSpec = SecLensSpec()
    realvuln: RealVulnSpec = RealVulnSpec()


# --------------------------------------------------------------------------- snapshots


def _group_id(repo_url: str, sha: str) -> str:
    return f"{g.repo_dir(Path('x'), repo_url).name.removesuffix('.git')}__{sha[:12]}"


def _snapshot(paths: Paths, repo_url: str, ref: str, *, tag: bool = False) -> tuple[str, Path]:
    """Bare clone + detached worktree at `ref`; returns (full sha, worktree dir)."""
    gd = g.ensure_repo(paths.repos, repo_url)
    if tag:
        g.git(["fetch", "--tags", "-q", "--filter=blob:none", "origin"], git_dir=gd, timeout=900)
        sha = g.git(["rev-parse", f"{ref}^{{commit}}"], git_dir=gd).stdout.strip()
    else:
        sha = g.fetch_commit(gd, ref, timeout=900)
    dest = paths.snapshots / "_groups" / _group_id(repo_url, sha)
    g.add_worktree(gd, sha, dest, timeout=1800)
    return sha, dest


def _item(iid: str, language: str, repo_url: str, vuln: str, cwe: list[str], gt: list[GTLocation],
          loc: int, source: str, note: str, fix: str = "") -> BenchmarkItem:
    return BenchmarkItem(id=iid, language=language, repo_url=repo_url, vuln_commit=vuln,
                         fix_commit=fix or vuln, cwe=cwe, loc=loc, gt_locations=gt,
                         split="dev", sources=[source], quality=Quality(label_ok=True, note=note))


def _in_scope_loc(worktree: Path, language: str) -> int:
    """External corpora are wholly in scope: the benchmark body is the product code."""
    bcfg = load_benchmark_config()
    return count_loc(worktree, bcfg.source_extensions[language], [])[0]


def _write(kind: str, paths: Paths, items: list[BenchmarkItem]) -> list[BenchmarkItem]:
    io.write_jsonl(paths.benchmark, items)
    log.info("%s: wrote %d items to %s", kind, len(items), paths.benchmark)
    return items


# --------------------------------------------------------------------------- builders


def _owasp_categories(lines: list[str]) -> dict[tuple[str, str], list[str]]:
    """(category, CWE) -> TRUE-labeled test names; skips the CSV comment header and FALSE rows."""
    by_cat: dict[tuple[str, str], list[str]] = defaultdict(list)
    for line in lines:
        parts = line.split(",")
        if len(parts) < 4 or parts[2].lower() not in ("true", "false"):
            continue
        if parts[2].lower() == "true":
            by_cat[(parts[1], f"CWE-{parts[3].strip()}")].append(parts[0])
    return by_cat


def build_owasp(kind: str, spec: OwaspSpec, paths: Paths, force: bool = False) -> list[BenchmarkItem]:
    """One item per vulnerability category; GT = whole TRUE-labeled test files (file-level labels)."""
    sha, worktree = _snapshot(paths, spec.repo, spec.ref)
    by_cat = _owasp_categories((worktree / spec.csv).read_text(encoding="utf-8-sig").splitlines())

    loc = _in_scope_loc(worktree, spec.language)
    items, missing = [], Counter()
    for (cat, cwe), names in sorted(by_cat.items()):
        gt = []
        for name in names:
            rel = f"{spec.testcode}/{name}{spec.extension}"
            f = worktree / rel
            if not f.exists():
                missing[cat] += 1
                continue
            gt.append(GTLocation(file=rel, kind="sink", start_line=1,
                                 end_line=len(f.read_text(encoding="utf-8", errors="replace").splitlines())))
        if gt:
            note = f"owasp labels at {spec.ref[:12]}"
            if missing[cat]:
                note += f"; {missing[cat]} test files not found"
            items.append(_item(f"owasp-{kind.removeprefix('owasp-')}-{cat}", spec.language, spec.repo,
                               sha, [cwe], gt, loc, "owasp-benchmark", note))
    return _write(kind, paths, items)


def _hf_jsonl(dataset: str, raw_dir: Path, force: bool = False) -> list[dict]:
    """Download every .jsonl file of a HuggingFace dataset and parse the rows.
    Gated datasets need HF_TOKEN in the environment."""
    import os

    headers = {"Authorization": f"Bearer {os.environ['HF_TOKEN']}"} if os.environ.get("HF_TOKEN") else None
    r = httpx.get(f"https://huggingface.co/api/datasets/{dataset}/tree/main", timeout=60,
                  follow_redirects=True, headers=headers)
    r.raise_for_status()
    rows: list[dict] = []
    for f in r.json():
        if not f["path"].endswith(".jsonl"):
            continue
        dest = download(f"https://huggingface.co/datasets/{dataset}/resolve/main/{f['path']}",
                        raw_dir / "seclens" / Path(f["path"]).name, force, headers=headers)
        rows += [json.loads(line) for line in dest.read_text(encoding="utf-8").splitlines() if line.strip()]
    return rows


def _seclens_item(t: dict, tasks: dict[str, dict]) -> BenchmarkItem | None:
    """One CVE pair: true_positive task -> item; None for unsupported languages / non-vulnerable."""
    if t.get("type") != "true_positive":
        return None
    lang = SUPPORTED.get((t["repository"].get("language") or "").lower())
    gt = t.get("ground_truth") or {}
    if lang is None or not gt.get("vulnerable"):
        return None
    pair = tasks.get((t.get("metadata") or {}).get("paired_with") or "")
    fix = pair["repository"]["commit"] if pair and pair.get("type") == "post_patch" else ""
    tgt = t["target"]
    loc = GTLocation(file=tgt["file"], kind="sink", start_line=int(tgt["line_start"]),
                     end_line=int(tgt["line_end"]), function=tgt.get("function"))
    if fix and pair:
        ptgt = pair["target"]
        loc.fixed_file, loc.fixed_start_line, loc.fixed_end_line = \
            ptgt["file"], int(ptgt["line_start"]), int(ptgt["line_end"])
    iid = "seclens-" + re.sub(r"[^A-Za-z0-9._-]+", "_", t["id"])[:90]
    return _item(iid, lang, t["repository"]["url"], t["repository"]["commit"],
                 [gt.get("cwe") or "CWE-693"], [loc], 0, "seclens",
                 f"seclens severity={gt.get('severity')}", fix=fix)


def build_seclens(spec: SecLensSpec, paths: Paths, force: bool = False) -> list[BenchmarkItem]:
    """CVE pairs: true_positive task = vulnerable side, its paired post_patch task = fixed side."""
    tasks = {t["id"]: t for t in _hf_jsonl(spec.dataset, paths.raw, force)}
    items = [it for it in (_seclens_item(t, tasks) for t in tasks.values()) if it is not None]
    skipped = len(tasks) - len(items)
    if skipped:
        log.info("seclens skipped: %d tasks (unsupported language or not vulnerable)", skipped)
    if spec.quota:
        items = items[:spec.quota]
    return _write("seclens", paths, items)


def _realvuln_gt(data: dict, whitelist: set[str]) -> tuple[list[GTLocation], list[str]]:
    """GT spans and CWE ranking (by labeled-finding count) for one repo's ground-truth.json."""
    gt, cwes = [], Counter()
    for x in data.get("findings") or []:
        if not x.get("is_vulnerable") or not x.get("location"):
            continue
        primary, acceptable = x.get("primary_cwe"), x.get("acceptable_cwes") or []
        cwe = primary if primary in whitelist else next((c for c in acceptable if c in whitelist), None)
        if not cwe:
            continue
        cwes[cwe] += 1
        gt.append(GTLocation(file=x["file"], kind="sink", start_line=int(x["location"]["start_line"]),
                             end_line=int(x["location"]["end_line"]), function=x.get("function")))
    return gt, [c for c, _ in cwes.most_common()]


def build_realvuln(spec: RealVulnSpec, paths: Paths, force: bool = False) -> list[BenchmarkItem]:
    """One item per pinned pre-patch repo; GT = hand-labeled true findings. No fixed side."""
    labels_dir = paths.raw / "realvuln" / "labels"
    git_clone_shallow(spec.labels_repo, labels_dir, force)
    wl = set(load_benchmark_config().cwe_whitelist)
    quota = spec.quota_per_language
    items, skipped, per_lang = [], Counter(), Counter()
    for d in sorted((labels_dir / "ground-truth").iterdir()):
        f = d / "ground-truth.json"
        if not f.is_file():
            continue
        data = json.loads(f.read_text(encoding="utf-8"))
        lang = SUPPORTED.get((data.get("language") or "").lower())
        if lang is None:
            skipped[f"language:{(data.get('language') or '?').lower()}"] += 1
            continue
        limit = quota.get(lang, 0) if isinstance(quota, dict) else quota
        if limit is not None and per_lang[lang] >= limit:
            skipped["quota"] += 1
            continue
        gt, cwes = _realvuln_gt(data, wl)
        if not gt:
            skipped["cwe_whitelist"] += 1
            continue
        try:
            sha, worktree = _snapshot(paths, data["repo_url"], data["commit_sha"])
            loc = _in_scope_loc(worktree, lang)
        except g.GitError as e:
            skipped["snapshot_error"] += 1
            log.warning("%s: snapshot failed: %s", data.get("repo_id"), str(e)[:200])
            continue
        iid = "rv-" + re.sub(r"[^A-Za-z0-9._-]+", "_", data.get("repo_id") or d.name)[:80]
        items.append(_item(iid, lang, data["repo_url"], sha, cwes,
                           gt, loc, "realvuln", "realvuln hand labels"))
        per_lang[lang] += 1
    if skipped:
        log.info("realvuln skipped: %s", dict(skipped))
    return _write("realvuln", paths, items)


BUILDERS = {"owasp-java": lambda c, p, f: build_owasp("owasp-java", c.owasp_java, p, f),
            "owasp-python": lambda c, p, f: build_owasp("owasp-python", c.owasp_python, p, f),
            "seclens": lambda c, p, f: build_seclens(c.seclens, p, f),
            "realvuln": lambda c, p, f: build_realvuln(c.realvuln, p, f)}


def build(kind: str, cfgx: ExternalConfig, paths: Paths | None = None, force: bool = False) -> list[BenchmarkItem]:
    return BUILDERS[kind](cfgx, paths or Paths(), force)


# --------------------------------------------------------------------------- scan + attribution


def _copy_scan(src: Path, dst: Path) -> None:
    """Attribute a group scan to one item: copy manifests, findings and raw reports."""
    dst.mkdir(parents=True, exist_ok=True)
    for f in src.iterdir():
        if f.is_file() and f.suffix in (".json", ".jsonl", ".sarif", ".txt"):
            shutil.copy2(f, dst / f.name)


def scan(kind: str, cfgx: ExternalConfig, tools: list[str] | None, sast_config: Path,
         paths: Paths | None = None, force: bool = False, summary: RunSummary | None = None) -> None:
    from app.sast import tools as toolmod
    from app.sast.run import run_tools
    from app.core.yaml_configs import load_sast_config

    paths = paths or Paths()
    cfg = load_sast_config(sast_config)
    toolmod.set_overrides(cfg.tool_paths)
    if tools is None:
        tools = [n for n, s in cfg.tools.items() if s.enabled]
    items = [BenchmarkItem.model_validate(r) for r in io.read_jsonl(paths.benchmark)]
    groups: dict[tuple[str, str, str], list[tuple[BenchmarkItem, Side]]] = defaultdict(list)
    for it in items:
        groups[(it.repo_url, it.vuln_commit, it.language)].append((it, "vuln"))
        if it.fix_commit and it.fix_commit != it.vuln_commit:
            groups[(it.repo_url, it.fix_commit, it.language)].append((it, "fixed"))

    summary = summary or RunSummary(f"external scan {kind}")
    for (repo_url, commit, language), members in sorted(groups.items()):
        gid = _group_id(repo_url, commit)
        sha, worktree = _snapshot(paths, repo_url, commit)
        out = paths.sast / "_groups" / gid
        run_tools(worktree, language, out, tools, cfg, item_id=gid, side=members[0][1], force=force)
        if any(it.loc == 0 for it, _ in members):
            loc = _in_scope_loc(worktree, language)
            for it, _ in members:
                it.loc = loc
            io.write_jsonl(paths.benchmark, items)
        for it, side in members:
            _copy_scan(out, paths.sast / it.id / side)
            summary.inc("attributed")
        log.info("%s: attributed to %d item sides", gid, len(members))
