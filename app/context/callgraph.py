"""Approximate name-based call graph (spec §5.2). Precision is not critical."""

from __future__ import annotations

from collections import defaultdict

import networkx as nx

from app.context.index import SnapshotIndex

MAX_TARGETS = 5   # a call name resolving to more functions than this is too ambiguous (get, run, ...)


def build_callgraph(idx: SnapshotIndex) -> nx.DiGraph:
    g = nx.DiGraph()
    by_name: dict[str, list] = defaultdict(list)
    for fn in idx.all_functions():
        g.add_node(fn.id, file=fn.file, name=fn.name, start=fn.start, end=fn.end)
        by_name[fn.simple_name].append(fn)
    for fn in idx.all_functions():
        for call in fn.calls:
            targets = by_name.get(call.name, [])
            if not targets:
                continue
            same_file = [t for t in targets if t.file == fn.file]
            chosen = same_file or (targets if len(targets) <= MAX_TARGETS else [])
            for t in chosen:
                if t.id != fn.id:
                    g.add_edge(fn.id, t.id, line=call.line)
    return g


def callers(g: nx.DiGraph, fid: str, depth: int = 2) -> list[tuple[str, int, int]]:
    """[(caller_id, call_line, distance)] breadth-first up to `depth`."""
    out, seen, frontier = [], {fid}, [fid]
    for d in range(1, depth + 1):
        nxt = []
        for node in frontier:
            if node not in g:
                continue
            for pred in g.predecessors(node):
                if pred in seen:
                    continue
                seen.add(pred)
                out.append((pred, g.edges[pred, node].get("line", 0), d))
                nxt.append(pred)
        frontier = nxt
    return out


def callees(g: nx.DiGraph, fid: str, depth: int = 2) -> list[tuple[str, int]]:
    out, seen, frontier = [], {fid}, [fid]
    for d in range(1, depth + 1):
        nxt = []
        for node in frontier:
            if node not in g:
                continue
            for succ in g.successors(node):
                if succ not in seen:
                    seen.add(succ)
                    out.append((succ, d))
                    nxt.append(succ)
        frontier = nxt
    return out


def to_json(g: nx.DiGraph) -> dict:
    return {"edges": [[u, v, d.get("line", 0)] for u, v, d in g.edges(data=True)]}


def from_json(data: dict, idx: SnapshotIndex) -> nx.DiGraph:
    g = nx.DiGraph()
    for fn in idx.all_functions():
        g.add_node(fn.id, file=fn.file, name=fn.name, start=fn.start, end=fn.end)
    for u, v, line in data.get("edges", []):
        g.add_edge(u, v, line=line)
    return g
