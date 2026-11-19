"""Stage A orchestration: sources -> candidate pool -> GT extraction -> stratified selection -> splits.

Every processed candidate is cached in work/cand/<key>.json, so re-runs are cheap and reproduce the
same selection (the order is a seeded shuffle).
"""

from __future__ import annotations

import hashlib
import math
import random
import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path

from app.core import io
from bench import git_utils as g
from bench.diff_gt import FileReader, compile_excludes, extract_gt, in_scope
from bench.schemas import BenchmarkItem, GTLocation, Quality, RawItem, repo_key
from bench.sources import ADAPTERS
from bench.sources import osv as osv_source
from bench.config import BenchmarkConfig, Paths, load_benchmark_config
from app.core.runlog import RunSummary, log
from app.sast.cwe_map import norm_cwe

SOURCE_RANK = {name: i for i, name in enumerate(ADAPTERS)}
FAMILY = {"python": "python", "javascript": "js", "typescript": "js"}


# ----------------------------------------------------------------------------- helpers


def family_extensions(cfg: BenchmarkConfig, language: str) -> list[str]:
    if FAMILY[language] == "python":
        return cfg.source_extensions["python"]
    return cfg.source_extensions["javascript"] + cfg.source_extensions["typescript"]


def normalize_cwes(cwes: list[str], cfg: BenchmarkConfig) -> list[str]:
    """Alias-fold, keep order, whitelisted first."""
    out: list[str] = []
    for c in cwes:
        n = norm_cwe(c)
        if not n:
            continue
        n = cfg.cwe_aliases.get(n, n)
        if n not in out:
            out.append(n)
    wl = set(cfg.cwe_whitelist)
    return [c for c in out if c in wl] + [c for c in out if c not in wl]


def snapshot_dir(item_id: str, side: str, paths: Paths | None = None) -> Path:
    return (paths or Paths()).snapshots / item_id / side


def load_items(split: str | None = None, paths: Paths | None = None) -> list[dict]:
    items = io.read_jsonl((paths or Paths()).benchmark)
    return [it for it in items if split is None or it["split"] == split]


def count_loc(root: Path, extensions: list[str], excludes: list[re.Pattern]) -> tuple[int, Counter]:
    """Non-blank lines in in-scope source files; also returns file counts per extension."""
    loc = 0
    exts: Counter = Counter()
    for p in root.rglob("*"):
        if not p.is_file() or ".git" in p.parts:
            continue
        rel = p.relative_to(root).as_posix()
        if not in_scope(rel, extensions, excludes):
            continue
        exts[p.suffix.lower()] += 1
        try:
            with open(p, "rb") as fh:
                loc += sum(1 for line in fh if line.strip())
        except OSError:
            pass
    return loc, exts


# ----------------------------------------------------------------------------- candidate pool


def collect_sources(cfg: BenchmarkConfig, paths: Paths, force: bool, summary: RunSummary) -> dict[str, list[RawItem]]:
    raw: dict[str, list[RawItem]] = {}
    meta = []
    for name, adapter in ADAPTERS.items():
        if not getattr(cfg.sources, name).enabled:
            continue
        try:
            meta.append(adapter.fetch(paths.raw, cfg, force))
            raw[name] = adapter.load(paths.raw, cfg)
            summary.inc(f"raw {name}", len(raw[name]))
        except Exception as e:  # noqa: BLE001
            summary.fail(f"source {name}: {e}")
    write_sources_md(paths, meta)
    return raw


def write_sources_md(paths: Paths, meta: list[dict]) -> None:
    lines = ["# Benchmark sources", "", "| Source | URL | Version | License | Note |", "|---|---|---|---|---|"]
    for m in meta:
        lines.append(f"| {m['name']} | {m['url']} | {m.get('version', '')} | {m.get('license', '')} | "
                     f"{m.get('note', '')} |")
    lines += ["", "## Not used", "",
              "| Source | Reason |", "|---|---|",
              "| RepoPairBench (DREA, arXiv 2607.13439) | no public data release found (checked 2026-11-18) |",
              "| CVEfixes | not needed: OSV + PyVul + PatchEval + SecBench.js give enough candidates |",
              "| NVD API 2.0 | OSV (GHSA-backed) already provides CVE, CWE, dates and fix commits |",
              "| CWE-Bench-Java / IRIS | Java; methodology reference only (one vuln per project) |",
              "| OWASP Juice Shop | sanity set, deferred |", ""]
    io.atomic_write_text(paths.raw / "SOURCES.md", "\n".join(lines))


def build_pool(raw: dict[str, list[RawItem]], cfg: BenchmarkConfig) -> list[dict]:
    """Merge sources by (repo, fix commit); enrich from OSV; keep whitelisted CWEs."""
    osv_items = raw.get("osv", [])
    osv_idx = osv_source.enrichment_index(osv_items)
    osv_by_cve: dict[str, RawItem] = {}
    for it in osv_items:
        if it.cve and (it.cve not in osv_by_cve or (it.published and osv_by_cve[it.cve].published
                                                   and it.published < osv_by_cve[it.cve].published)):
            osv_by_cve[it.cve] = it

    pool: dict[tuple[str, str], dict] = {}
    for name in ADAPTERS:  # priority order
        for it in raw.get(name, []):
            k = it.key
            short = (k[0], k[1][:12])
            existing = pool.get(k) or next((v for kk, v in pool.items() if kk[0] == k[0]
                                            and (kk[1].startswith(k[1]) or k[1].startswith(kk[1]))), None) \
                if len(k[1]) < 40 else pool.get(k)
            if existing is None:
                existing = pool[k] = {
                    "repo_url": it.repo_url, "fix_commit": it.fix_commit, "language": it.language,
                    "cve": None, "ghsa": None, "published": None, "cwe_raw": [], "sources": [],
                    "has_poc": False, "multi_commit": False, "extra": {},
                }
            e = existing
            if name not in e["sources"]:
                e["sources"].append(name)
            e["cve"] = e["cve"] or it.cve
            e["ghsa"] = e["ghsa"] or it.ghsa
            e["published"] = e["published"] or it.published
            e["cwe_raw"] += [c for c in it.cwe if c not in e["cwe_raw"]]
            e["has_poc"] = e["has_poc"] or it.has_poc
            if name != "osv" or len(e["sources"]) == 1:
                e["multi_commit"] = e["multi_commit"] or it.multi_commit
            for kx, vx in it.extra.items():
                if vx is not None and kx not in e["extra"]:
                    e["extra"][kx] = vx
            o = osv_idx.get(k) or osv_idx.get(short)
            if o is None and e["cve"]:
                o = osv_by_cve.get(e["cve"])
            if o is not None and name != "osv":
                e["cve"] = e["cve"] or o.cve
                e["ghsa"] = e["ghsa"] or o.ghsa
                e["published"] = e["published"] or o.published
                e["cwe_raw"] += [c for c in o.cwe if c not in e["cwe_raw"]]

    wl = set(cfg.cwe_whitelist)
    out = []
    for (rk, sha), e in pool.items():
        cwes = normalize_cwes(e["cwe_raw"], cfg)
        if not cwes or cwes[0] not in wl:
            continue
        e["cwe"] = cwes
        e["primary_cwe"] = cwes[0]
        e["key"] = f"{rk.split('github.com/')[-1].replace('/', '__')}__{sha[:12]}"
        e["best_source"] = min(SOURCE_RANK[s] for s in e["sources"])
        out.append(e)
    out.sort(key=lambda e: e["key"])
    assign_ids(out)
    return out


def assign_ids(pool: list[dict]) -> None:
    seen: Counter = Counter()
    for e in pool:
        prefix = "py" if FAMILY[e["language"]] == "python" else "js"
        if e["cve"]:
            base = f"{prefix}-{e['cve']}"
        elif e["ghsa"]:
            base = f"{prefix}-{e['ghsa']}"
        else:
            owner_repo = e["repo_url"].split("github.com/")[-1].replace("/", "-")
            base = f"{prefix}-{owner_repo}-{e['fix_commit'][:7]}"
        seen[base] += 1
        e["id"] = base if seen[base] == 1 else f"{base}-{e['fix_commit'][:7]}"


# ----------------------------------------------------------------------------- per-candidate processing


def process_candidate(c: dict, cfg: BenchmarkConfig, paths: Paths, force: bool = False) -> dict:
    cache = paths.work / "cand" / f"{c['key']}.json"
    if cache.exists() and not force:
        return io.read_json(cache)
    res = _process(c, cfg, paths)
    res["key"] = c["key"]
    res["id"] = c["id"]
    if res.get("reason") not in ("error",):  # don't cache unexpected/transient errors
        io.write_json(cache, res)
    return res


def _reject(reason: str, **kw) -> dict:
    return {"status": "rejected", "reason": reason, **kw}


def _process(c: dict, cfg: BenchmarkConfig, paths: Paths) -> dict:
    excludes = compile_excludes(cfg.path_excludes)
    exts = family_extensions(cfg, c["language"])
    try:
        gd = g.ensure_repo(paths.repos, c["repo_url"])
        fix = g.fetch_commit(gd, c["fix_commit"], timeout=cfg.clone_timeout_s)
    except g.GitError as e:
        return _reject("fetch_failed", detail=str(e)[:300])
    ps = g.parents(gd, fix)
    if not ps:
        return _reject("root_commit")
    vuln = ps[0]
    notes = ["merge commit: first parent used"] if len(ps) > 1 else []
    try:
        tree = g.ls_files(gd, vuln)
    except g.GitError as e:
        return _reject("tree_failed", detail=str(e)[:300])
    src_files = [p for p in tree if in_scope(p, exts, excludes)]
    if not src_files:
        return _reject("no_source_files")
    if len(src_files) > cfg.target.max_source_files:
        return _reject("too_large_prefilter", source_files=len(src_files))

    reader = FileReader(lambda sha, path: g.show_file(gd, sha, path))
    try:
        diff = g.diff_u0(gd, vuln, fix)
    except g.GitError as e:
        return _reject("diff_failed", detail=str(e)[:300])
    gt = extract_gt(diff, vuln, fix, reader, exts, excludes, cfg.tangled.max_files,
                    cfg.tangled.max_changed_lines, sink=c["extra"].get("sink"),
                    vul_funcs=c["extra"].get("vul_funcs"), vuln_tree=tree)
    if not any(loc.kind == "fix_hunk" for loc in gt.locations):
        return _reject("no_in_scope_hunks", notes=gt.notes[:5])

    # sparse checkout (source files only) of the vulnerable snapshot to count LOC;
    # `bench checkout` later turns it into a full worktree for accepted items
    dest = snapshot_dir(c["id"], "vuln", paths)
    try:
        g.add_worktree(gd, vuln, dest, timeout=cfg.clone_timeout_s,
                       sparse_patterns=[f"*{e}" for e in exts])
    except g.GitError as e:
        return _reject("checkout_failed", detail=str(e)[:300])
    loc, ext_counts = count_loc(dest, exts, excludes)
    language = c["language"]
    if FAMILY[language] == "js":
        ts = sum(ext_counts[e] for e in cfg.source_extensions["typescript"])
        js = sum(ext_counts[e] for e in cfg.source_extensions["javascript"])
        language = "typescript" if ts > js else "javascript"
    lo, hi = cfg.loc_bounds[language]
    if not lo <= loc <= hi:
        g.remove_worktree(gd, dest)
        return _reject("loc_out_of_bounds", loc=loc)
    return {
        "status": "ok", "vuln_commit": vuln, "fix_commit": fix, "language": language, "loc": loc,
        "gt_locations": [x.model_dump(mode="json") for x in gt.locations],
        "files_changed": gt.files_changed, "lines_changed": gt.lines_changed, "tangled": gt.tangled,
        "notes": notes + gt.notes[:10],
    }


# ----------------------------------------------------------------------------- selection


class Selector:
    """Round-robin over CWE buckets, best source first, with per-CWE and per-repo caps."""

    def __init__(self, cands: list[dict], quota: int, cwe_cap: int, seed: int, per_repo: int,
                 used_repos: Counter):
        rng = random.Random(seed)
        buckets: dict[str, list[dict]] = defaultdict(list)
        for c in cands:
            buckets[c["primary_cwe"]].append(c)
        for b in buckets.values():
            rng.shuffle(b)
            b.sort(key=lambda c: c["best_source"])  # stable: shuffled within source rank
        self.order = sorted(buckets)
        rng.shuffle(self.order)
        self.buckets = buckets
        self.quota, self.cwe_cap, self.per_repo = quota, cwe_cap, per_repo
        self.accepted: list[tuple[dict, dict]] = []
        self.cwe_count: Counter = Counter()
        self.used_repos = used_repos
        self.pending: Counter = Counter()
        self.attempts = 0

    @property
    def done(self) -> bool:
        return len(self.accepted) >= self.quota

    def next_batch(self, n: int) -> list[dict]:
        batch: list[dict] = []
        progressed = True
        while len(batch) < n and progressed and len(self.accepted) + sum(self.pending.values()) < self.quota * 2:
            progressed = False
            for cwe in self.order:
                if len(batch) >= n:
                    break
                room = self.cwe_cap - self.cwe_count[cwe]
                # overcommit 2x: many candidates get rejected (LOC bounds, no in-scope hunks, ...)
                if room <= 0 or self.pending[cwe] >= max(2, 2 * room):
                    continue
                b = self.buckets[cwe]
                while b:
                    c = b.pop(0)
                    if self.used_repos[repo_key(c["repo_url"])] >= self.per_repo:
                        continue
                    batch.append(c)
                    self.pending[cwe] += 1
                    progressed = True
                    break
        return batch

    def offer(self, c: dict, res: dict) -> bool:
        self.pending[c["primary_cwe"]] -= 1
        self.attempts += 1
        if res.get("status") != "ok" or res.get("tangled") or self.done:
            return False
        if self.cwe_count[c["primary_cwe"]] >= self.cwe_cap:
            return False
        if self.used_repos[repo_key(c["repo_url"])] >= self.per_repo:
            return False
        self.accepted.append((c, res))
        self.cwe_count[c["primary_cwe"]] += 1
        self.used_repos[repo_key(c["repo_url"])] += 1
        return True


def run_selector(sel: Selector, cfg: BenchmarkConfig, paths: Paths, force: bool, summary: RunSummary,
                 label: str, log_rows: list, extra_sink: list, max_attempts: int) -> None:
    with ThreadPoolExecutor(max_workers=cfg.workers) as pool:
        while not sel.done and sel.attempts < max_attempts:
            batch = sel.next_batch(cfg.workers * 2)
            if not batch:
                break
            results = list(pool.map(lambda c: _safe_process(c, cfg, paths, force), batch))
            for c, res in zip(batch, results):
                ok = sel.offer(c, res)
                status = "accepted" if ok else ("tangled" if res.get("tangled") else
                                                res.get("reason", "not_needed"))
                summary.inc(f"{label} {status}")
                log_rows.append({"id": c["id"], "pool": label, "repo_url": c["repo_url"],
                                 "fix_commit": c["fix_commit"], "cwe": c["primary_cwe"],
                                 "sources": c["sources"], "status": status,
                                 "detail": res.get("detail") or res.get("loc") or res.get("source_files")})
                if res.get("status") == "ok" and res.get("tangled"):
                    extra_sink.append((c, res))
                elif res.get("status") == "ok" and not ok:
                    # processed but not selected: free the snapshot
                    _drop_snapshot(c, paths)
            log.info("%s: %d/%d accepted after %d attempts", label, len(sel.accepted), sel.quota, sel.attempts)


def _safe_process(c: dict, cfg: BenchmarkConfig, paths: Paths, force: bool) -> dict:
    try:
        return process_candidate(c, cfg, paths, force)
    except Exception as e:  # noqa: BLE001
        log.warning("%s: unexpected error: %s", c["id"], e)
        return _reject("error", detail=str(e)[:300])


def _drop_snapshot(c: dict, paths: Paths) -> None:
    dest = snapshot_dir(c["id"], "vuln", paths)
    if dest.exists():
        g.remove_worktree(g.repo_dir(paths.repos, c["repo_url"]), dest)
        try:
            dest.parent.rmdir()
        except OSError:
            pass


def to_item(c: dict, res: dict, split: str) -> BenchmarkItem:
    return BenchmarkItem(
        id=c["id"], language=res["language"], repo_url=c["repo_url"], vuln_commit=res["vuln_commit"],
        fix_commit=res["fix_commit"], cve=c["cve"], ghsa=c["ghsa"], cwe=c["cwe"],
        published=c["published"], loc=res["loc"],
        gt_locations=[GTLocation.model_validate(x) for x in res["gt_locations"]],
        has_poc=c["has_poc"], split=split, sources=c["sources"],
        quality=Quality(tangled=res["tangled"], multi_commit=c["multi_commit"]),
        files_changed=res["files_changed"], lines_changed=res["lines_changed"],
    )


def build(config_path: Path, limit: int | None = None, force: bool = False,
          summary: RunSummary | None = None) -> list[BenchmarkItem]:
    cfg = load_benchmark_config(config_path)
    paths = Paths()
    summary = summary or RunSummary("bench build")
    raw = collect_sources(cfg, paths, force, summary)
    pool = build_pool(raw, cfg)
    io.write_jsonl(paths.work / "pool.jsonl", pool)
    summary.inc("pool (whitelisted)", len(pool))

    cutoff: date = cfg.post_cutoff_date
    t = cfg.target
    seed = cfg.seed
    used_repos: Counter = Counter()
    log_rows: list[dict] = []
    tangled_found: list[tuple[dict, dict]] = []

    def eligible(c, post: bool, lang_family: str) -> bool:
        if FAMILY[c["language"]] != lang_family or c["multi_commit"]:
            return False
        is_post = bool(c["published"] and date.fromisoformat(str(c["published"])) >= cutoff)
        return is_post == post

    main_total = limit if limit else t.main_items
    py_quota = math.ceil(main_total * t.python_share)
    quotas = {"python": py_quota, "js": main_total - py_quota}
    selected: dict[str, list[tuple[dict, dict]]] = {}
    for fam, q in quotas.items():
        cap = max(1, math.floor(t.max_cwe_share * q)) if not limit else q
        sel = Selector([c for c in pool if eligible(c, False, fam)], q, cap, seed, t.max_items_per_repo,
                       used_repos)
        run_selector(sel, cfg, paths, force, summary, f"main-{fam}", log_rows, tangled_found,
                     t.max_attempts_per_language)
        selected[f"main-{fam}"] = sel.accepted
        if not sel.done:
            summary.notes.append(f"main-{fam}: only {len(sel.accepted)}/{q} items")

    if not limit:
        for fam in ("python", "js"):
            q = t.post_cutoff_items // 2
            cap = max(1, math.floor(t.post_cutoff_max_cwe_share * q))
            sel = Selector([c for c in pool if eligible(c, True, fam)], q, cap, seed + 1,
                           t.max_items_per_repo, used_repos)
            run_selector(sel, cfg, paths, force, summary, f"post-{fam}", log_rows, tangled_found,
                         t.max_attempts_per_language // 2)
            selected[f"post-{fam}"] = sel.accepted

    # splits
    rng = random.Random(seed)
    items: list[BenchmarkItem] = []
    main_py, main_js = selected["main-python"], selected["main-js"]
    dev_n = 0 if limit else t.dev_size
    dev_ids = set()
    for group in (main_py, main_js):
        ids = sorted(c["id"] for c, _ in group)
        rng.shuffle(ids)
        dev_ids |= set(ids[: dev_n // 2])
    if limit:
        dev_ids = {c["id"] for c, _ in main_py + main_js}  # smoke runs: everything is dev
    for c, res in main_py + main_js:
        items.append(to_item(c, res, "dev" if c["id"] in dev_ids else "test"))
    for key in ("post-python", "post-js"):
        for c, res in selected.get(key, []):
            items.append(to_item(c, res, "post_cutoff"))
    if not limit:
        seen_ids = {it.id for it in items}
        for c, res in sorted(tangled_found, key=lambda x: x[0]["id"])[: t.extra_items]:
            if c["id"] not in seen_ids:
                items.append(to_item(c, res, "extra"))
                seen_ids.add(c["id"])

    items.sort(key=lambda it: ({"dev": 0, "test": 1, "post_cutoff": 2, "extra": 3}[it.split], it.id))
    # keep the manual-check verdicts from a previous build
    prev = {it["id"]: it for it in io.read_jsonl(paths.benchmark)}
    for it in items:
        if it.id in prev and prev[it.id].get("quality", {}).get("manually_checked"):
            q = prev[it.id]["quality"]
            it.quality.manually_checked = True
            it.quality.label_ok = q.get("label_ok")
            it.quality.note = q.get("note")
    io.write_jsonl(paths.benchmark, items)
    io.write_jsonl(paths.candidates, log_rows)
    removed = cleanup_orphan_snapshots({it.id: it.repo_url for it in items}, pool, paths)
    if removed:
        summary.inc("orphan snapshots removed", removed)
    summary.inc("benchmark items", len(items))
    for split, n in sorted(Counter(it.split for it in items).items()):
        summary.inc(f"split {split}", n)
    summary.notes.append(f"wrote {paths.benchmark}")
    return items


# ----------------------------------------------------------------------------- checkout


def checkout_all(split: str | None = None, limit: int | None = None, force: bool = False,
                 summary: RunSummary | None = None) -> None:
    paths = Paths()
    cfg = load_benchmark_config()
    summary = summary or RunSummary("bench checkout")
    items = load_items(split, paths)
    if limit:
        items = items[:limit]

    def one(it: dict) -> tuple[str, str | None]:
        try:
            gd = g.ensure_repo(paths.repos, it["repo_url"])
            g.fetch_commit(gd, it["fix_commit"], timeout=cfg.clone_timeout_s)
            for side, sha in (("vuln", it["vuln_commit"]), ("fixed", it["fix_commit"])):
                dest = snapshot_dir(it["id"], side, paths)
                if force and dest.exists():
                    g.remove_worktree(gd, dest)
                g.add_worktree(gd, sha, dest, timeout=cfg.clone_timeout_s)
                head = g.git(["rev-parse", "HEAD"], cwd=dest).stdout.strip()
                if head != sha:
                    return it["id"], f"{side}: HEAD {head} != {sha}"
            return it["id"], None
        except Exception as e:  # noqa: BLE001
            return it["id"], str(e)[:300]

    with ThreadPoolExecutor(max_workers=cfg.workers) as pool:
        for item_id, err in pool.map(one, items):
            if err:
                summary.fail(f"{item_id}: {err}")
            else:
                summary.inc("checked out")


def cleanup_orphan_snapshots(keep: dict[str, str], pool: list[dict], paths: Paths) -> int:
    """Remove snapshot dirs of candidates that did not make it into benchmark.jsonl."""
    if not paths.snapshots.exists():
        return 0
    repo_of = {c["id"]: c["repo_url"] for c in pool}
    n = 0
    for d in paths.snapshots.iterdir():
        if d.name in keep or not d.is_dir():
            continue
        repo = repo_of.get(d.name)
        for side in ("vuln", "fixed"):
            if (d / side).exists():
                if repo:
                    g.remove_worktree(g.repo_dir(paths.repos, repo), d / side)
                else:
                    import shutil

                    shutil.rmtree(d / side, ignore_errors=True)
        try:
            d.rmdir()
            n += 1
        except OSError:
            pass
    for gd in paths.repos.glob("*.git"):
        g.git(["worktree", "prune"], git_dir=gd, check=False)
    return n


def item_hash(it: BenchmarkItem) -> str:
    return hashlib.sha256(io.dumps(it).encode()).hexdigest()[:12]
