"""Checks for the cross-corpus comparison renderer."""

from __future__ import annotations

from bench.compare import _coverage_line, _pool


def test_pool_ignores_subgroup_keys_and_weights_by_n():
    metrics = {
        "dev": {"S": {"n": 2, "recall@10": 1.0, "mrr": 1.0}},
        "test": {"S": {"n": 2, "recall@10": 0.5, "mrr": 0.5}},
        # aggregate() subgroup keys must not leak into the pooled row
        "dev/cwe/CWE-79": {"S": {"n": 1, "recall@10": 0.0, "mrr": 0.0}},
    }
    rows = _pool(metrics)
    assert rows["S"]["n"] == 4
    assert rows["S"]["recall@10"] == 0.75
    assert rows["S"]["mrr"] == 0.75


def test_coverage_line_sums_splits_and_hides_empty_tools():
    coverage = {
        "dev": {"bandit": {"ok": 2, "applicable": 2, "seconds": 3.0},
                "joern": {"not_applicable": 2}},
        "test": {"bandit": {"ok": 1, "applicable": 2, "timeout": 1}},
    }
    line = _coverage_line(coverage)
    assert "bandit 3/4 ok (1 timeout)" in line
    assert "joern" not in line  # nothing applicable
