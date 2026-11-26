"""Prioritization (WP8): priority = S · E · R.

A ranking heuristic, not a probability. `rank_by_S` (sorting by sink severity alone) is kept on every flow
so the evaluation can check whether S·E·R improves recall@k over S.
"""

from __future__ import annotations

from app.llmflow.models import Flow


def score(f: Flow) -> float:
    return round(f.S * f.E * f.R, 4)


def rank(flows: list[Flow]) -> list[Flow]:
    for f in flows:
        f.priority = score(f)
    by_s = sorted(flows, key=lambda f: (-f.S, len(f.hops), f.sink.file, f.sink.line))
    for i, f in enumerate(by_s, 1):
        f.rank_by_S = i
    out = sorted(flows, key=lambda f: (-f.priority, -f.S, len(f.hops), f.sink.file, f.sink.line))
    for i, f in enumerate(out, 1):
        f.rank = i
    return out
