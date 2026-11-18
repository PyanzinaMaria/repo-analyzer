"""Mode D — vulnerability discovery without (L) or with (D+, hybrid) SAST hints.

Candidate functions are ranked by attack surface (entry points, sinks, risky names) and sent to the model
in groups; answers are deduplicated and ranked by confidence x severity. Used by the analyzer service and
by the benchmark runner (bench/llm.py).
"""

from __future__ import annotations

import math
import re
from concurrent.futures import ThreadPoolExecutor

from app.context.callgraph import callees
from app.context.sinks import catalog_text, function_sinks
from app.context.slicer import Snapshot, make_pack
from app.ai.llm import LLMClient
from app.ai.common import assert_no_leak, redact_ids
from app.ai.prompting import render
from app.ai.schemas import DiscoveredVuln, DiscoveryResult
from app.core.runlog import RunSummary
from app.sast.cwe_map import cwe_overlap
from app.sast.normalize import MergedFinding

RISKY_PATH = re.compile(r"(request|view|route|api|handler|controller|upload|download|file|auth|login|logout|session|"
                        r"serial|pickle|yaml|parse|template|render|exec|shell|cmd|command|proxy|fetch|url|"
                        r"redirect|merge|extend|util|path|archive|zip|tar|xml|query|sql|db|admin|token|jwt|"
                        r"verify|sign|password|passwd|crypto|cookie|middleware|permission|role|acl|grant)", re.I)
# auth/crypto decisions are invisible to the sink catalog; reward functions that make them
AUTH_CALL = re.compile(r"(jwt|verify|decode|sign|JSON\.parse|atob|Buffer\.from|compare|hash|hmac|"
                       r"check_password|authenticate|is_admin|has_perm)", re.I)

SEVERITY_WEIGHT = {"CWE-78": 1.0, "CWE-94": 1.0, "CWE-95": 1.0, "CWE-502": 1.0, "CWE-89": 1.0,
                   "CWE-22": 0.9, "CWE-918": 0.9, "CWE-611": 0.9, "CWE-1321": 0.85, "CWE-287": 0.85,
                   "CWE-862": 0.8, "CWE-863": 0.8, "CWE-79": 0.75, "CWE-352": 0.7, "CWE-601": 0.65,
                   "CWE-1333": 0.6}


def severity_weight(cwe: str) -> float:
    return SEVERITY_WEIGHT.get(cwe, 0.7)


def score_functions(snap: Snapshot) -> list[tuple[float, str]]:
    """Candidate score: entry point, sink in function, sink within 2 hops, risky file/function name."""
    lang = snap.idx.language
    has_sink = {fid for fid, fn in snap.funcs.items() if function_sinks(fn, lang)}
    # reachable from an entry point within 2 calls
    reach: set[str] = set()
    for ep in snap.entrypoints:
        reach |= {c for c, _ in callees(snap.graph, ep, depth=2)}
    # lexical parent (callbacks nested in a function inherit its reachability)
    by_file: dict[str, list] = {}
    for fn in snap.funcs.values():
        by_file.setdefault(fn.file, []).append(fn)

    def parent(fn):
        outer = [o for o in by_file[fn.file] if o.id != fn.id and o.start <= fn.start and o.end >= fn.end]
        return min(outer, key=lambda o: o.end - o.start) if outer else None

    scored = []
    for fid, fn in snap.funcs.items():
        if fn.end - fn.start < 2 or fn.name.startswith("<anonymous"):
            continue
        s = 0.0
        if fid in snap.entrypoints:
            s += 3.0
        else:
            p = parent(fn)
            if fid in reach or (p is not None and (p.id in reach or p.id in snap.entrypoints)):
                s += 1.0
        if fid in has_sink:
            s += 2.5
        elif any(c in has_sink for c, _ in callees(snap.graph, fid, depth=2)):
            s += 1.5
        if RISKY_PATH.search(fn.file) or RISKY_PATH.search(fn.name):
            s += 1.0
        if any(AUTH_CALL.search(c.callee) for c in fn.calls):
            s += 1.0
        if s >= 2.5:   # needs more than a risky name alone
            scored.append((s + min(fn.end - fn.start, 200) / 1000.0, fid))
    scored.sort(reverse=True)
    return scored


def n_candidates(loc: int, base: int, cap: int) -> int:
    return max(base, min(cap, base + int(math.log2(max(loc, 1000) / 1000) * 2)))


def aggregate(vulns: list[dict], tol: int = 3) -> list[dict]:
    """Dedupe (same file, |line diff| <= tol, related CWE), keep max confidence, rank conf x severity."""
    out: list[dict] = []
    for v in sorted(vulns, key=lambda v: -v["confidence"]):
        dup = next((o for o in out if o["file"] == v["file"] and abs(o["start_line"] - v["start_line"]) <= tol
                    and (o["cwe"] == v["cwe"] or cwe_overlap([o["cwe"]], [v["cwe"]]))), None)
        if dup:
            dup["support"] += 1
            continue
        out.append({**v, "support": 1})
    for o in out:
        o["score"] = round(o["confidence"] * severity_weight(o["cwe"]), 4)
    return sorted(out, key=lambda o: (-o["score"], o["file"], o["start_line"]))


def discover_functions(client: LLMClient, model_id: str, snap: Snapshot, language: str, loc: int,
                       merged: list[MergedFinding] | None = None, n_base: int = 6, n_cap: int = 12,
                       per_prompt: int = 5, budget_tokens: int = 10000, summary: RunSummary | None = None,
                       tag: str = "discover") -> list[dict] | None:
    """Ranked findings, or None when some prompts are still pending (export mode).

    `merged` (hybrid mode, D+): SAST findings used as hints; their functions become candidates too."""
    summary = summary or RunSummary(tag)
    merged = list(merged or [])
    picks = [fid for _, fid in score_functions(snap)][: n_candidates(loc, n_base, n_cap)]
    # make sure functions with SAST findings are candidates too (hybrid mode)
    for m in merged:
        fn = snap.idx.function_at(m.file, m.start_line)
        if fn and fn.id not in picks and len(picks) < n_cap + 4:
            picks.append(fn.id)
    groups = [picks[i:i + per_prompt] for i in range(0, len(picks), per_prompt)]
    sinks = catalog_text(language)
    per_fn_budget = max(1200, budget_tokens // max(1, per_prompt))
    valid_files = set(snap.idx.files)

    def one(group: list[str]) -> list[dict]:
        cands, hints = [], []
        for fid in group:
            fn = snap.funcs[fid]
            pack = make_pack(snap, fn.file, fn.start, fn.end, budget_tokens=per_fn_budget)
            cands.append({"entry": snap.entrypoints.get(fid), "context": redact_ids(pack.text)})
            for m in merged:
                if m.file == fn.file and fn.start <= m.start_line <= fn.end:
                    hints.append({"file": m.file, "start_line": m.start_line, "tools": m.tools, "cwe": m.cwe,
                                  "message": (m.messages[0] if m.messages else "")[:200]})
        system, user = render("discovery", language=language, sinks=sinks, candidates=cands,
                              sast_hints=hints)
        assert_no_leak(system, user)
        res = client.complete_json(model_id, system, user, DiscoveryResult,
                                   params={"max_tokens": 3000},
                                   tag=tag)
        summary.cost_usd += res.cost
        if res.pending:
            summary.inc("pending")
            return None
        if res.obj is None:
            summary.inc("invalid/missing")
            return []
        summary.inc("ok")
        rows = []
        for v in res.obj.vulnerabilities:
            v = _fix_path(v, valid_files)
            if v is None:
                summary.inc("hallucinated file")
                continue
            rows.append({**v.model_dump(), "origin_functions": group})
        return rows

    workers = client.cfg.backends[client.spec(model_id).backend].max_concurrency
    found: list[dict] = []
    pending = False
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for rows in ex.map(one, groups):
            if rows is None:
                pending = True
            else:
                found += rows
    return None if pending else aggregate(found)


def _fix_path(v: DiscoveredVuln, valid: set[str]) -> DiscoveredVuln | None:
    if v.file in valid:
        return v
    f = v.file.lstrip("./")
    if f in valid:
        v.file = f
        return v
    cands = [p for p in valid if p.endswith("/" + f) or f.endswith("/" + p)]
    if len(cands) == 1:
        v.file = cands[0]
        return v
    return None
