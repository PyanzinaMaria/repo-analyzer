"""Benchmark manifest and matching (no network, no Semgrep)."""

from __future__ import annotations

from app.llmflow.bench import EntryResult, load_manifest, match, summarize


def test_taintp2x_manifest_is_complete():
    m = load_manifest("taintp2x35")
    assert len(m.entries) == 35
    assert len({e.id for e in m.entries}) == 35
    published = {k: sum(e.reported.get(k) == "Y" for e in m.entries) for k in ("llmsmith", "agentfuzz", "taintp2x")}
    assert published == {"llmsmith": 17, "agentfuzz": 7, "taintp2x": 27}       # TaintP2X Table 2 totals
    assert {e.cls for e in m.entries} == {"code_injection", "sql_injection", "file_rw", "ssrf"}
    assert sum(e.scope == "app" for e in m.entries) == 15


def _flow(rank, sink_class, file, func, rank_by_S=None):
    return {"rank": rank, "rank_by_S": rank_by_S or rank, "sink_class": sink_class, "priority": 0.5,
            "gated": False, "hops": [{"file": "x.py", "func_name": "ask", "line": 1, "role": "llm"},
                                     {"file": file, "func_name": func, "line": 9, "role": "sink"}]}


def test_match_requires_file_func_and_class():
    e = next(x for x in load_manifest().entries if x.id == "P21")       # Vanna exec
    flows = [_flow(1, "sql", "src/vanna/base/base.py", "VannaBase.get_plotly_figure"),   # wrong class
             _flow(2, "code_eval", "src/vanna/other.py", "VannaBase.get_plotly_figure"),  # wrong file
             _flow(3, "code_eval", "src/vanna/base/base.py", "VannaBase.get_plotly_figure"),
             _flow(4, "code_eval", "src/vanna/base/base.py", "VannaBase.get_plotly_figure")]
    assert match(e, flows)["rank"] == 3
    assert match(e, flows[:2]) is None


def test_summarize_recall_and_at_k():
    rs = [EntryResult("a", "c1", "code_injection", "app", "r", "v", detected=True, rank=1, rank_by_S=4,
                      reported={"taintp2x": "Y"}),
          EntryResult("b", "c2", "sql_injection", "app", "r", "v", detected=True, rank=5, rank_by_S=2,
                      reported={"taintp2x": "N"}),
          EntryResult("c", "c3", "code_injection", "framework", "r", "v", reported={"taintp2x": "Y"})]
    s = summarize(rs)
    assert s["all"]["llmflow"] == {"hit": 2, "n": 3, "recall": 0.667}
    assert s["all"]["taintp2x"]["hit"] == 2
    assert s["app"]["llmflow_at_k"] == {1: 1, 3: 1, 10: 2}
    assert s["app"]["S_only_at_k"] == {1: 0, 3: 1, 10: 2}
