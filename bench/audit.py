"""`python -m bench audit show <item>`: audit document for one benchmark snapshot, optionally with the
known vulnerability (ground truth) overlaid. Everything is read from disk; no API calls."""

from __future__ import annotations

from collections import Counter

from app.core import io
from app.services.report.audit import CONFIG_PREFERENCE, AuditData
from bench.build import load_items, snapshot_dir
from bench.config import Paths
from bench.context import context_dir
from bench.eval.match import first_hits, function_hit, gt_spans
from bench.llm import out_dir
from bench.rank import build_rankings


def collect(item_id: str, side: str = "vuln", model: str | None = None, config: str | None = None,
            paths: Paths | None = None) -> AuditData:
    paths = paths or Paths()
    items = {it["id"]: it for it in load_items(None, paths)}
    if item_id not in items:
        raise SystemExit(f"unknown item: {item_id}")
    item = items[item_id]
    models = [model] if model else []
    ranks = build_rankings(item_id, side, models, paths)
    if config is None:
        config = next((f"{c}@{model}" for c in CONFIG_PREFERENCE if model and f"{c}@{model}" in ranks), "S")
    elif model and config != "S" and not config.startswith("S-") and "@" not in config:
        config = f"{config}@{model}"
    if config not in ranks:
        raise SystemExit(f"no outputs for config {config!r}; available: {', '.join(sorted(ranks)) or 'none'}")

    data = AuditData(item=item, side=side, model=model, config=config, ranked=ranks[config],
                     root=snapshot_dir(item_id, side, paths),
                     commit=item["vuln_commit"] if side == "vuln" else item["fix_commit"])
    cdir = context_dir(item_id, side, paths)
    if (cdir / "summary.json").exists():
        data.context = io.read_json(cdir / "summary.json")
        data.entry_kinds = Counter(io.read_json(cdir / "entrypoints.json").values())
        data.sink_cwes = Counter(s["cwe"] for s in io.read_json(cdir / "sinks.json"))
    sdir = paths.sast / item_id / side
    for st in sorted(sdir.glob("*.status.json")):
        s = io.read_json(st)
        data.sast[s["tool"]] = {"ok": s["ok"], "seconds": s.get("seconds", 0)}
    for f in io.read_jsonl(sdir / "findings.jsonl"):
        if f["tool"] in data.sast:
            data.sast[f["tool"]]["findings"] = data.sast[f["tool"]].get("findings", 0) + 1
    if model:
        tri = out_dir(model, "triage", paths) / item_id / f"{side}.jsonl"
        if tri.exists():
            data.removed = [r for r in io.read_jsonl(tri) if r.get("result") and r["score"] == 0]

    # ground-truth comparison (benchmark mode only)
    gts = gt_spans(item, side)
    resolver = None
    idx_path = cdir / "index.json"
    if idx_path.exists():
        from app.context.index import load_index

        data.idx = idx = load_index(idx_path)

        def resolver(f, ln):
            fn = idx.function_at(f, ln)
            return (fn.start, fn.end) if fn else None
    for key, lst in ranks.items():
        if key.startswith("S-"):
            continue
        data.gt_ranks[key] = first_hits(lst, gts, 5, resolver, item["cwe"]).func_rank
    data.gt_locations = gts
    data.gt_hit = lambda e: any(function_hit(e, g, resolver, 5) for g in gts)
    return data
