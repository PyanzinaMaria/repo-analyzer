"""Code context for one source tree: index, call graph, entry points and sinks (written as JSON)."""

from __future__ import annotations

from pathlib import Path

from app.context.callgraph import build_callgraph, from_json, to_json
from app.context.entrypoints import detect_entrypoints, package_main
from app.context.index import build_index, load_index
from app.context.sinks import function_sinks
from app.context.slicer import Snapshot
from app.core import io
from app.core.yaml_configs import load_sast_config


def build_snapshot_context(root: Path, language: str, out: Path, force: bool = False) -> dict:
    """Index `root` and write index/callgraph/entrypoints/sinks/summary JSON into `out` (cached)."""
    if (out / "index.json").exists() and not force:
        return io.read_json(out / "summary.json")
    cfg = load_sast_config()
    idx = build_index(root, language, cfg.family_extensions(language), cfg.path_excludes)
    graph = build_callgraph(idx)
    eps = detect_entrypoints(idx, package_main(root) if language != "python" else None)
    sinks = [h.__dict__ for fn in idx.all_functions() for h in function_sinks(fn, language)]
    io.write_json(out / "index.json", idx)
    io.write_json(out / "callgraph.json", to_json(graph))
    io.write_json(out / "entrypoints.json", eps)
    io.write_json(out / "sinks.json", sinks)
    summary = {"files": len(idx.files), "functions": sum(len(f.functions) for f in idx.files.values()),
               "edges": graph.number_of_edges(), "entrypoints": len(eps), "sinks": len(sinks)}
    io.write_json(out / "summary.json", summary)
    return summary


def load_context(root: Path, ctx_dir: Path) -> Snapshot:
    """Snapshot (code root + index + call graph + entry points) from a directory written by
    build_snapshot_context."""
    idx = load_index(ctx_dir / "index.json")
    graph = from_json(io.read_json(ctx_dir / "callgraph.json"), idx)
    eps = io.read_json(ctx_dir / "entrypoints.json")
    return Snapshot(root, idx, graph, eps)
