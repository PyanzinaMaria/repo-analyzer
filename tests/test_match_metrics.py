import math

from bench.eval.match import GTSpan, first_hits, flagged_within, function_hit, gt_spans, line_hit
from bench.eval.metrics import bootstrap_ci, mcnemar, mrr, pair_acc, prf, recall_at_k

ITEM = {
    "gt_locations": [
        {"file": "app/views.py", "kind": "fix_hunk", "start_line": 120, "end_line": 124,
         "function": "download", "function_start": 110, "function_end": 140,
         "fixed_file": "app/views.py", "fixed_start_line": 120, "fixed_end_line": 128,
         "fixed_function": "download", "fixed_function_start": 110, "fixed_function_end": 144},
        {"file": "app/util.py", "kind": "fix_hunk", "start_line": 5, "end_line": 5,
         "function": None, "function_start": None, "function_end": None},
    ]
}


def E(file, line, end=None, cwe=None):
    return {"file": file, "start_line": line, "end_line": end or line, "cwe": cwe or []}


def test_gt_spans_sides():
    v = gt_spans(ITEM, "vuln")
    f = gt_spans(ITEM, "fixed")
    assert len(v) == 2 and len(f) == 1
    assert f[0].fn_end == 144


def test_line_hit_tolerance():
    g = gt_spans(ITEM, "vuln")[0]
    assert line_hit(E("app/views.py", 115), g, tol=5)       # 115+5 reaches 120
    assert not line_hit(E("app/views.py", 114), g, tol=5)
    assert line_hit(E("app/views.py", 129), g, tol=5)
    assert not line_hit(E("app/other.py", 120), g, tol=5)


def test_function_hit_with_and_without_resolver():
    g = gt_spans(ITEM, "vuln")[0]
    assert function_hit(E("app/views.py", 135), g, None, 5)
    assert not function_hit(E("app/views.py", 150), g, None, 5)
    # nested function inside download -> resolver says different span -> no hit
    resolver = lambda f, ln: (130, 136) if 130 <= ln <= 136 else (110, 140)  # noqa: E731
    assert not function_hit(E("app/views.py", 133), g, resolver, 5)
    assert function_hit(E("app/views.py", 112), g, resolver, 5)


def test_module_level_gt_falls_back_to_lines():
    g = gt_spans(ITEM, "vuln")[1]
    assert function_hit(E("app/util.py", 9), g, None, 5)
    assert not function_hit(E("app/util.py", 30), g, None, 5)


def test_vuln_function_kind_counts_whole_span():
    g = GTSpan("a.py", 10, 40, 10, 40, "vuln_function")
    assert function_hit(E("a.py", 39), g, None, 5)
    assert not function_hit(E("a.py", 45), g, None, 5)


def test_first_hits_and_flagged():
    ranked = [E("app/db.py", 40), E("app/views.py", 138, cwe=["CWE-22"]), E("app/views.py", 121)]
    gts = gt_spans(ITEM, "vuln")
    hi = first_hits(ranked, gts, tol=5, item_cwes=["CWE-22"])
    assert hi.func_rank == 2 and hi.line_rank == 3 and hi.cwe_agree is True
    assert flagged_within(ranked, gts, 1, 5) is False
    assert flagged_within(ranked, gts, 2, 5) is True
    assert flagged_within(ranked, gts, 2, 5, level="line") is False


def test_long_function_guard():
    gts = [GTSpan("a.py", 500, 501, 1, 900, "fix_hunk")]
    hi = first_hits([E("a.py", 3)], gts, tol=5, max_fn_lines=300)
    assert hi.func_rank == 1 and hi.func_hit_long_fn


def test_recall_mrr_pairacc():
    ranks = [1, 3, None, 12]
    assert recall_at_k(ranks, 1) == 0.25
    assert recall_at_k(ranks, 5) == 0.5
    assert recall_at_k(ranks, 20) == 0.75
    assert math.isclose(mrr(ranks), (1 + 1 / 3 + 0 + 1 / 12) / 4)
    assert pair_acc([True, True, False], [False, True, False]) == 1 / 3
    assert math.isnan(recall_at_k([], 5))


def test_bootstrap_and_mcnemar():
    lo, hi = bootstrap_ci([1.0] * 8 + [0.0] * 2, n=2000)
    assert 0.5 <= lo <= 0.8 <= hi <= 1.0
    r = mcnemar([True, True, False, False, True], [True, False, True, True, True])
    assert r["a_only"] == 1 and r["b_only"] == 2 and 0 < r["p_value"] <= 1
    assert mcnemar([True], [True])["p_value"] == 1.0


def test_prf():
    m = prf(tp=8, fp=2, fn=8)
    assert m["precision"] == 0.8 and m["recall"] == 0.5
    assert math.isclose(m["f1"], 2 * 0.8 * 0.5 / 1.3)
