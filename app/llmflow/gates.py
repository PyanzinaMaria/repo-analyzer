"""Gates and exposure (WP5).

A gate counts for a flow when it matched in a function on the flow's path *after* the LLM hop, at or
before the line where the path leaves that function, applies to the flow's sink class and, if the gate
binds $V, mentions an identifier of the tainted value at that hop.
"""

from __future__ import annotations

from typing import Callable

from app.context.index import SnapshotIndex
from app.llmflow.catalog import Catalog
from app.llmflow.models import GateHit, Hop, Match
from app.llmflow.stitch import gate_overlap


def gate_hits(cat: Catalog, matches: list[Match], idx: SnapshotIndex) -> list[GateHit]:
    by_id = {g.id: g for g in cat.gates.gates}
    out = []
    seen = set()
    for m in matches:
        if m.family != "gate":
            continue
        g = by_id.get(m.meta.get("gate", ""))
        if g is None or (m.file, m.line, g.id) in seen:
            continue
        seen.add((m.file, m.line, g.id))
        fn = idx.function_at(m.file, m.line)
        out.append(GateHit(gate=g.id, kind=g.kind, title=g.title, factor=cat.gates.factors[g.kind],
                           file=m.file, line=m.line, func=fn.id if fn else None, var=m.fields.get("V") or ""))
    return out


def _hop_value(h: Hop) -> str:
    """Text of the tainted value at a hop: the label after ':' / '←', or the code line."""
    for sep in (": ", "← "):
        if sep in h.label:
            return h.label.split(sep, 1)[1] + " " + h.code
    return h.code


LoopLookup = Callable[[str, int, int], "tuple[int, int] | None"]


def _in_window(g_line: int, entry: int, exit_: int, loop: tuple[int, int] | None) -> bool:
    """Does a gate at g_line run after the LLM output enters the function (entry) and before it leaves (exit_)?

    Straight-line code: entry ≤ gate ≤ exit. When the output enters *after* the exit line inside a loop
    (produced in one iteration, used in the next — a REPL that asks before running the previous answer),
    the path is entry → end of loop body → loop start → exit."""
    if entry <= exit_:
        return entry <= g_line <= exit_
    if loop is None:
        return False
    start, end = loop
    return entry <= g_line <= end or start <= g_line <= exit_


def gates_on_path(cat: Catalog, hops: list[Hop], sink_class: str, gates: list[GateHit],
                  loops: LoopLookup | None = None) -> list[GateHit]:
    by_id = {g.id: g for g in cat.gates.gates}
    llm_i = next((i for i, h in enumerate(hops) if h.role in ("llm", "tool")), 0)
    # the line where LLM output enters each function bounds the gates there (checks before it don't count)
    after: dict[str | None, int] = {}
    for h in hops[llm_i:]:
        after.setdefault(h.func, h.line)
    found: dict[str, GateHit] = {}
    for h in hops[llm_i + 1:]:
        if h.func is None:
            continue
        value = _hop_value(h)
        entry = after.get(h.func, 0)
        loop = loops(h.file, h.line, entry) if loops and entry > h.line else None
        for g in gates:
            spec = by_id.get(g.gate)
            if spec is None or g.func != h.func or not spec.applies(sink_class):
                continue
            if not _in_window(g.line, entry, h.line, loop):
                continue
            if spec.kind != "confirmation" and not gate_overlap(g.var, value):
                continue
            found.setdefault(f"{g.gate}@{g.file}:{g.line}", g)
    return list(found.values())


def exposure(E_base: float, gates: list[GateHit]) -> float:
    return E_base * (min(g.factor for g in gates) if gates else 1.0)
