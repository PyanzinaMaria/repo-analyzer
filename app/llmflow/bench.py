"""Benchmark harness: real vulnerabilities at their vulnerable versions (config/llmflow/bench/*.yaml).

  fetch    shallow-clone every (repo, ref) into data/llmflow/bench/repos/
  check    every entry's expected file exists in its checkout (catches wrong refs / paths in the manifest)
  run      scan each checkout once, match findings to entries, write results + a comparison table

An entry is detected when a flow has a hop whose file matches `expect.file` and whose function matches
`expect.func`, and the flow's sink class is allowed for the entry's class. The rank of the best matching
flow is recorded too, so recall@k can be compared with ranking by S alone (`rank_by_S`).
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from app.core.yaml_configs import REPO_ROOT
from app.llmflow.catalog import LLMFLOW_DIR

BENCH_DIR = REPO_ROOT / "data" / "llmflow" / "bench"
CLASS_SINKS = {
    "code_injection": {"code_eval", "shell", "deserialize"},
    "sql_injection": {"sql"},
    "file_rw": {"file_write", "text"},
    "ssrf": {"http"},
}


class Expect(BaseModel):
    file: str
    func: str = "."
    sink: str | None = None      # optional regex on the sink hop's function (pins the vulnerable call)


class Entry(BaseModel):
    id: str
    cve: str
    cls: str = Field(alias="class")
    scope: str
    repo: str
    ref: str
    path: str = ""
    exclude: list[str] = Field(default_factory=list)   # extra paths to skip (monorepo packages)
    expect: Expect
    note: str = ""
    reported: dict[str, str] = Field(default_factory=dict)

    @property
    def checkout(self) -> Path:
        return BENCH_DIR / "repos" / f"{self.repo.replace('/', '__')}@{re.sub(r'[^A-Za-z0-9._-]', '_', self.ref)}"

    @property
    def target(self) -> Path:
        return self.checkout / self.path if self.path else self.checkout


class Manifest(BaseModel):
    source: str = ""
    entries: list[Entry]


def load_manifest(name: str = "taintp2x35") -> Manifest:
    p = Path(name)
    if not p.exists():
        p = LLMFLOW_DIR / "bench" / f"{name}.yaml"
    return Manifest.model_validate(yaml.safe_load(p.read_text(encoding="utf-8")))


# --------------------------------------------------------------------------------------------- fetch


def _git(args: list[str], cwd: Path | None = None, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout)


def fetch(entry: Entry) -> str:
    """Shallow checkout of entry.repo at entry.ref; returns 'cached', 'ok' or an error message."""
    dest = entry.checkout
    if (dest / ".git").exists():
        return "cached"
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/{entry.repo}.git"
    is_sha = bool(re.fullmatch(r"[0-9a-f]{40}", entry.ref))
    if not is_sha:
        r = _git(["clone", "--quiet", "--depth", "1", "--branch", entry.ref, "-c", "core.longpaths=true",
                  url, str(dest)])
        return "ok" if r.returncode == 0 else f"clone failed: {r.stderr.strip()[-300:]}"
    dest.mkdir(parents=True, exist_ok=True)
    for args in (["init", "--quiet"], ["config", "core.longpaths", "true"], ["remote", "add", "origin", url],
                 ["fetch", "--quiet", "--depth", "1", "origin", entry.ref], ["checkout", "--quiet", "FETCH_HEAD"]):
        r = _git(args, cwd=dest)
        if r.returncode != 0:
            return f"git {args[0]} failed: {r.stderr.strip()[-300:]}"
    return "ok"


def check(entry: Entry) -> list[str]:
    """Files under the scan target that match expect.file (empty = the manifest entry is wrong)."""
    rx = re.compile(entry.expect.file)
    root = entry.target
    if not root.exists():
        return []
    return [p.relative_to(root).as_posix() for p in root.rglob("*.py") if rx.search(p.relative_to(root).as_posix())]


# --------------------------------------------------------------------------------------------- run


@dataclass
class EntryResult:
    id: str
    cve: str
    cls: str
    scope: str
    repo: str
    ref: str
    detected: bool = False
    rank: int | None = None
    rank_by_S: int | None = None
    priority: float | None = None
    gated: bool = False
    flow: str | None = None
    flows_in_repo: int = 0
    callsites_in_repo: int = 0
    seconds: float = 0.0
    error: str | None = None
    reported: dict = field(default_factory=dict)


def match(entry: Entry, flows: list[dict]) -> dict | None:
    """Best (lowest rank) flow matching the entry, or None."""
    rf, rfn = re.compile(entry.expect.file), re.compile(entry.expect.func)
    allowed = CLASS_SINKS[entry.cls]
    best = None
    for f in flows:
        if f["sink_class"] not in allowed:
            continue
        if entry.expect.sink and not re.search(entry.expect.sink, f["hops"][-1].get("func_name") or ""):
            continue
        if any(rf.search(h["file"]) and rfn.search(h.get("func_name") or "") for h in f["hops"]):
            if best is None or f["rank"] < best["rank"]:
                best = f
    return best


def run_bench(entries: list[Entry], opts=None, progress=None, rescan: bool = False) -> list[EntryResult]:
    from app.llmflow.pipeline import Options, run

    say = progress or (lambda _m: None)
    opts = opts or Options()
    scans: dict[Path, tuple[list[dict], dict, float, str | None]] = {}
    results = []
    for e in entries:
        res = EntryResult(e.id, e.cve, e.cls, e.scope, e.repo, e.ref, reported=e.reported)
        target = e.target
        if target not in scans:
            cfg = "fw" if getattr(opts, "frameworks", False) else "sdk"
            out = BENCH_DIR / "out" / cfg / f"{e.checkout.name}{'__' + e.path.replace('/', '_') if e.path else ''}"
            cached = out / "findings.json"
            if cached.exists() and not rescan:
                scans[target] = (json.loads(cached.read_text(encoding="utf-8")),
                                 json.loads((out / "summary.json").read_text(encoding="utf-8")), 0.0, None)
            elif not target.exists():
                scans[target] = ([], {}, 0.0, "not fetched")
            else:
                say(f"{e.id} {e.repo}@{e.ref}: scanning…")
                t0 = time.monotonic()
                try:
                    r = run(target, out, replace(opts, excludes=list(opts.excludes) + e.exclude))
                    scans[target] = ([f.to_dict() for f in r.flows], r.summary(), time.monotonic() - t0, None)
                except Exception as ex:  # noqa: BLE001 — one broken checkout must not stop the benchmark
                    scans[target] = ([], {}, time.monotonic() - t0, f"{type(ex).__name__}: {ex}"[:300])
        flows, summary, secs, err = scans[target]
        res.error, res.seconds = err, round(summary.get("seconds", secs) or secs, 1)
        res.flows_in_repo, res.callsites_in_repo = len(flows), summary.get("callsites", 0)
        m = match(e, flows)
        if m:
            res.detected, res.rank, res.rank_by_S = True, m["rank"], m["rank_by_S"]
            res.priority, res.gated = m["priority"], m["gated"]
            res.flow = " → ".join(f"{h['func_name'] or '?'}:{h['line']}" for h in m["hops"]
                                  if h["role"] in ("source", "llm", "tool", "sink"))
        results.append(res)
    return results


def summarize(results: list[EntryResult]) -> dict:
    def recall(rs, key=None):
        n = len(rs)
        if key is None:
            hit = sum(r.detected for r in rs)
        else:
            hit = sum(r.reported.get(key) == "Y" for r in rs)
        return {"hit": hit, "n": n, "recall": round(hit / n, 3) if n else None}

    out = {}
    for scope in ("all", "app", "framework"):
        rs = [r for r in results if scope == "all" or r.scope == scope]
        out[scope] = {"llmflow": recall(rs), **{k: recall(rs, k) for k in ("taintp2x", "llmsmith", "agentfuzz")}}
        hits = [r for r in rs if r.detected]
        out[scope]["llmflow_at_k"] = {k: sum(1 for r in hits if r.rank <= k) for k in (1, 3, 10)}
        out[scope]["S_only_at_k"] = {k: sum(1 for r in hits if r.rank_by_S <= k) for k in (1, 3, 10)}
    return out


def write_results(results: list[EntryResult], dest: Path) -> dict:
    dest.mkdir(parents=True, exist_ok=True)
    summ = summarize(results)
    (dest / "results.json").write_text(json.dumps({"summary": summ, "entries": [asdict(r) for r in results]},
                                                  indent=2, ensure_ascii=False), encoding="utf-8")
    return summ
