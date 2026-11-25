"""LLM-flow pipeline: catalog → rules → Semgrep passes → inventory → stitching → gates/E → R → ranking.

Standalone: takes a local directory, needs only Semgrep. It does not touch the scan orchestrator, the
worker or `meta.runners` (docs/SPEC.md), so the UI contract stays as it is.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from app.context.entrypoints import detect_entrypoints
from app.context.index import build_index
from app.core.yaml_configs import load_sast_config
from app.llmflow.astutil import SourceCache
from app.llmflow.catalog import Catalog, load_catalog
from app.llmflow.gates import exposure, gate_hits, gates_on_path
from app.llmflow.inventory import build_inventory, with_sdk_aliases
from app.llmflow.kb import r_value
from app.llmflow.models import CallSite, Flow, GateHit, Match
from app.llmflow.rank import rank
from app.llmflow.rulegen import pass_rules, static_rules, write_rules
from app.llmflow.semgrep import run_rules
from app.llmflow.stitch import Exposure, RawFlow, Stitcher

TEST_GLOBS = ["tests", "test", "testing", "__tests__", "test_*.py", "*_test.py", "conftest.py"]
INDEX_EXCLUDES = [
    r"(^|/)(node_modules|vendor|vendored|third_party|site-packages|\.venv|venv|build|dist)/",
]
TEST_EXCLUDES = [r"(^|/)(tests?|testing|__tests__)/", r"(^|/)(test_[^/]*|[^/]*_test|conftest)\.py$"]


@dataclass
class Options:
    max_depth: int = 3
    extra_sinks: set[str] = field(default_factory=set)
    include_tests: bool = False
    excludes: list[str] = field(default_factory=list)
    jobs: int = 4
    timeout_s: int = 1200


@dataclass
class PassStat:
    n: int
    rules: int
    matches: int
    seconds: float
    wrappers: int = 0
    s_fragments: int = 0
    i_fragments: int = 0


@dataclass
class Result:
    root: str
    repo_name: str
    callsites: list[CallSite]
    flows: list[Flow]
    exposures: list[Exposure]
    gates: list[GateHit]
    hygiene: list[dict]
    passes: list[PassStat]
    seconds: float
    files: int
    functions: int
    errors: list[str] = field(default_factory=list)
    wrappers: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        by_class: dict[str, int] = {}
        for f in self.flows:
            by_class[f.sink_class] = by_class.get(f.sink_class, 0) + 1
        return {
            "repo": self.repo_name, "files": self.files, "functions": self.functions,
            "callsites": len(self.callsites),
            "models": sorted({c.model.name or "?" for c in self.callsites}),
            "tools": sum(len(c.tools) for c in self.callsites),
            "exposed_callsites": sum(1 for c in self.callsites if c.exposure),
            "flows": len(self.flows), "gated": sum(1 for f in self.flows if f.gated),
            "flows_by_sink": by_class, "hygiene": len(self.hygiene),
            "wrappers": self.wrappers, "passes": [asdict(p) for p in self.passes],
            "seconds": round(self.seconds, 1), "errors": self.errors,
        }


Progress = Callable[[str], None]


def _semgrep_excludes(opts: Options) -> list[str]:
    ex = list(load_sast_config().exclude_dirs) + list(opts.excludes)
    if not opts.include_tests:
        ex += TEST_GLOBS
    return ex


def _hygiene(matches: list[Match], src: SourceCache) -> list[dict]:
    out, seen = [], set()
    for m in matches:
        if m.family != "hygiene" or (m.rule_id, m.file, m.line) in seen:
            continue
        seen.add((m.rule_id, m.file, m.line))
        out.append({"rule": m.rule_id.removeprefix("llmflow.").removeprefix("hygiene."),
                    "severity": m.meta.get("severity"),
                    "cwe": m.meta.get("cwe"), "message": m.message, "file": m.file, "line": m.line,
                    "code": src.line(m.file, m.line)})
    return sorted(out, key=lambda h: (h["file"], h["line"]))


def _collapse(flows: list[Flow]) -> list[Flow]:
    """One finding per (sink, sink class, untrusted source, gated?): the variants that differ only in the LLM
    call site in between (one per backend class) are folded into `alt_callsites` of the best one."""
    groups: dict[tuple, list[Flow]] = {}
    for f in flows:
        f.priority = round(f.S * f.E * f.R, 4)
        src = (f.hops[0].file, f.hops[0].line) if f.source_kind != "unknown" else ("unknown", 0)
        key = (f.sink.file, f.sink.line, f.sink_class, src, f.gated, f.channel == "tool_call")
        groups.setdefault(key, []).append(f)
    out = []
    for fs in groups.values():
        fs.sort(key=lambda f: (-f.priority, f.approx, len(f.hops)))
        best = fs[0]
        best.alt_callsites = sorted({f.callsite for f in fs[1:] if f.callsite and f.callsite != best.callsite})
        out.append(best)
    return out


def build_flows(cat: Catalog, st: Stitcher, gates: list[GateHit]) -> list[Flow]:
    exps: dict[str, list[Exposure]] = {}
    for e in st.facts.exposures:
        exps.setdefault(e.callsite, []).append(e)

    def pick_exposure(rf: RawFlow) -> Exposure | None:
        """Prefer a source in a function that is on the flow's path (same request handler), then max E."""
        cands = exps.get(rf.callsite or "", [])
        if not cands:
            return None
        on_path = {h.func for h in rf.hops if h.func}
        return max(cands, key=lambda e: (e.chain[0].func in on_path, bool({h.func for h in e.chain} & on_path),
                                         e.E, -len(e.chain)))

    # one flow per (sink location, sink class, LLM call site): keep the shortest path
    chosen: dict[tuple, RawFlow] = {}
    for rf in st.facts.flows:
        sink = rf.hops[-1]
        path_funcs = frozenset(h.func for h in rf.hops if h.role in ("call", "sink", "tool"))
        key = (sink.file, sink.line, rf.sink_class, rf.callsite, rf.via_tool, path_funcs)
        if key not in chosen or len(rf.hops) < len(chosen[key].hops):
            chosen[key] = rf
    flows = []
    d = cat.sources.defaults
    for rf in chosen.values():
        cs = st.cs_by_id.get(rf.callsite or "")
        exp = pick_exposure(rf)
        hops = (exp.chain + rf.hops) if exp else list(rf.hops)
        sc = cat.sinks.classes[rf.sink_class]
        f = Flow(id="", sink_class=rf.sink_class, sink_title=sc.title, cwe=sc.cwe, channel=rf.channel, hops=hops,
                 callsite=rf.callsite, model=cs.model.name if cs else None,
                 source_kind=exp.kind if exp else "unknown",
                 source_title=exp.title if exp else "unknown prompt provenance")
        f.S = sc.S
        f.E_base = exp.E if exp else d.unknown
        f.gates = gates_on_path(cat, hops, rf.sink_class, gates, loops=st.src.enclosing_loop)
        f.E = round(exposure(f.E_base, f.gates), 4)
        f.R, _ = r_value(cat.kb, f.model, rf.channel)
        f.approx = any(h.approx for h in hops)
        flows.append(f)
    flows = rank(_collapse(flows))
    for f in flows:
        f.id = f"LF{f.rank:03d}"
    return flows


def run(root: Path | str, out_dir: Path | str, opts: Options | None = None,
        progress: Progress | None = None) -> Result:
    t0 = time.monotonic()
    opts = opts or Options()
    root = Path(root).resolve()
    out_dir = Path(out_dir).resolve()
    (out_dir / "rules").mkdir(parents=True, exist_ok=True)
    say = progress or (lambda _m: None)
    cat = load_catalog()
    excludes = _semgrep_excludes(opts)

    say("indexing code (tree-sitter)…")
    idx_ex = INDEX_EXCLUDES + ([] if opts.include_tests else TEST_EXCLUDES) + [
        r"(^|/)" + e.replace(".", r"\.").replace("*", "[^/]*") + "(/|$)" for e in opts.excludes]
    idx = build_index(root, "python", [".py"], idx_ex)
    entry = detect_entrypoints(idx)
    src = SourceCache(root)
    cat, aliases = with_sdk_aliases(cat, idx, src)
    if aliases:
        say(f"SDK aliases: {', '.join(a.split(' = ')[0] for a in aliases)}")

    passes: list[PassStat] = []
    errors: list[str] = []

    def semgrep_pass(n: int, rules: list[dict]) -> list[Match]:
        say(f"semgrep pass {n}: {len(rules)} rules…")
        t = time.monotonic()
        rf = write_rules(rules, out_dir / "rules" / f"pass{n}.yaml")
        matches, errs = run_rules(root, rf, out_dir / "semgrep_raw" / f"pass{n}.json", excludes,
                                  timeout_s=opts.timeout_s, jobs=opts.jobs)
        errors.extend(f"pass{n}: {e.get('type')}: {str(e.get('message', ''))[:200]}" for e in errs[:20])
        passes.append(PassStat(n, len(rules), len(matches), round(time.monotonic() - t, 1)))
        return matches

    m0 = semgrep_pass(0, static_rules(cat, opts.extra_sinks))
    callsites = build_inventory(root, cat, m0, idx, src)
    st = Stitcher(cat, idx, src, callsites, entry)
    st.process(m0)

    def stat_last() -> None:
        p = passes[-1]
        p.wrappers = len(st.facts.R)
        p.s_fragments = sum(len(v) for v in st.facts.S.values())
        p.i_fragments = sum(len(v) for v in st.facts.I.values())

    stat_last()
    prev_wrappers: list[str] = []
    for n in range(1, opts.max_depth + 1):
        wrappers = st.wrapper_names()
        new_w = wrappers != prev_wrappers
        targets = st.new_fn_targets()
        if not new_w and not targets:
            break
        rules = pass_rules(cat, wrappers, st.all_s_targets(), targets, new_w, opts.extra_sinks)
        prev_wrappers = wrappers
        if not rules:
            break
        st.process(semgrep_pass(n, rules))
        stat_last()

    st.entry_exposures()
    st.tool_flows()
    for e in st.facts.exposures:
        cs = st.cs_by_id.get(e.callsite)
        if cs is not None:
            cs.exposure.append({"kind": e.kind, "E": e.E, "title": e.title,
                                "source": f"{e.chain[0].file}:{e.chain[0].line}", "hops": len(e.chain)})
    gates = gate_hits(cat, m0, idx)
    flows = build_flows(cat, st, gates)
    res = Result(root=str(root), repo_name=root.name, callsites=callsites, flows=flows,
                 exposures=st.facts.exposures, gates=gates, hygiene=_hygiene(m0, src), passes=passes,
                 seconds=time.monotonic() - t0, files=len(idx.files),
                 functions=sum(len(f.functions) for f in idx.files.values()), errors=errors,
                 wrappers=st.wrapper_names())
    write_outputs(res, out_dir)
    return res


def write_outputs(res: Result, out_dir: Path) -> None:
    def dump(name: str, data) -> None:
        (out_dir / name).write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    dump("inventory.json", [asdict(c) for c in res.callsites])
    dump("findings.json", [f.to_dict() for f in res.flows])
    dump("hygiene.json", res.hygiene)
    dump("summary.json", res.summary())
