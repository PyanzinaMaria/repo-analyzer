from pathlib import Path

from bench.config import load_benchmark_config
from app.context.callgraph import build_callgraph, callers
from app.context.entrypoints import detect_entrypoints
from app.context.index import analyze_source, build_index, js_exports
from app.context.sinks import function_sinks
from app.context.slicer import Snapshot, make_pack
from app.ai.discovery import aggregate, score_functions

FIX = Path(__file__).parent / "fixtures"


def _snap(name, lang):
    cfg = load_benchmark_config()
    exts = cfg.source_extensions["python"] if lang == "python" else cfg.source_extensions["javascript"]
    root = FIX / name
    idx = build_index(root, lang, exts, [])
    g = build_callgraph(idx)
    return Snapshot(root, idx, g, detect_entrypoints(idx))


def test_python_index_entrypoints_and_sinks():
    snap = _snap("toy-py-flask", "python")
    names = {fn.name: fid for fid, fn in snap.funcs.items()}
    assert {"ping", "download", "user", "config", "session"} <= set(names)
    assert all(snap.entrypoints.get(names[n]) == "route" for n in ("ping", "download", "user"))
    ping_sinks = function_sinks(snap.funcs[names["ping"]], "python")
    assert any(s.cwe == "CWE-78" for s in ping_sinks)
    assert any(s.cwe == "CWE-502" for s in function_sinks(snap.funcs[names["session"]], "python"))
    assert any(s.cwe == "CWE-89" for s in function_sinks(snap.funcs[names["user"]], "python"))


def test_js_index_callgraph_exports():
    snap = _snap("toy-js-express", "javascript")
    names = {fn.name: fid for fid, fn in snap.funcs.items()}
    assert "merge" in names
    assert snap.entrypoints[names["merge"]] == "exported_api"
    route = [n for n in names if n.startswith("app.get(")]
    assert len(route) >= 3 and all(snap.entrypoints[names[n]] == "route" for n in route)
    # merge is called by the /settings handler and by itself
    callers_of_merge = {snap.funcs[c].name for c, _, _ in callers(snap.graph, names["merge"])}
    assert any(n.startswith("app.post(") for n in callers_of_merge)


def test_js_exports_regexes():
    src = "module.exports = { merge, run: doRun };\nexports.x = 1;\nexport function y() {}\nexport default z"
    assert {"merge", "doRun", "x", "y", "default"} <= set(js_exports(src))


def test_analyze_source_calls_and_imports():
    fi = analyze_source("a.py", b"import os\nfrom x import y\n\ndef f(p):\n    os.system('ls ' + p)\n    y(p)\n")
    assert fi.imports == ["import os", "from x import y"]
    [fn] = fi.functions
    assert [c.callee for c in fn.calls] == ["os.system", "y"]


def test_slicer_budget_and_sections():
    snap = _snap("toy-js-express", "javascript")
    pack = make_pack(snap, "server.js", 26, budget_tokens=6000)
    assert pack.function == "merge" and pack.tokens <= 6000
    assert "callers" in pack.sections and ">   26 |" in pack.text
    small = make_pack(snap, "server.js", 26, budget_tokens=150)
    assert small.tokens <= 160 and small.sections == ["target"]


def test_discovery_candidate_scoring_prefers_routes_with_sinks():
    snap = _snap("toy-py-flask", "python")
    top = [snap.funcs[fid].name for _, fid in score_functions(snap)[:5]]
    assert set(top) == {"ping", "download", "user", "config", "session"}


def test_discovery_aggregate_dedup_and_rank():
    vs = [{"file": "a.py", "start_line": 10, "end_line": 10, "cwe": "CWE-22", "confidence": 0.6},
          {"file": "a.py", "start_line": 12, "end_line": 12, "cwe": "CWE-23", "confidence": 0.9},
          {"file": "b.py", "start_line": 3, "end_line": 3, "cwe": "CWE-78", "confidence": 0.8}]
    out = aggregate(vs)
    assert len(out) == 2 and out[0]["file"] == "b.py"      # 0.8*1.0 > 0.9*0.9
    assert next(o for o in out if o["file"] == "a.py")["support"] == 2
