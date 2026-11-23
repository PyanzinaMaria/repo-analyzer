"""Ranked lists per configuration for a benchmark (item, side), read from stage outputs on disk."""

from __future__ import annotations

from pathlib import Path

from app.ai.rank import rank_L, rank_S, rank_ST, rrf
from app.core import io
from app.core.yaml_configs import in_product_code
from app.sast.normalize import Finding, MergedFinding, merge
from bench.config import Paths
from bench.llm import out_dir


def load_merged(item_id: str, side: str, paths: Paths) -> list[MergedFinding] | None:
    """Merged SAST findings in product code only (findings in tests/examples/vendor are dropped)."""
    p = paths.sast / item_id / side / "merged.jsonl"
    if not p.exists():
        return None
    ms = [MergedFinding.model_validate(r) for r in io.read_jsonl(p)]
    return [m for m in ms if in_product_code(m.file)]


def _read(path: Path) -> list[dict] | None:
    return io.read_jsonl(path) if path.exists() else None


def build_rankings(item_id: str, side: str, models: list[str], paths: Paths | None = None) -> dict[str, list[dict]]:
    """{config_key: ranked list}; config_key is 'S', 'S-codeql', or '<config>@<model>'."""
    paths = paths or Paths()
    out: dict[str, list[dict]] = {}
    merged = load_merged(item_id, side, paths)
    directory = paths.sast / item_id / side
    manifest = directory / "runs.json"
    S = None
    if merged is not None:
        if manifest.exists():
            run = io.read_json(manifest)
            successful = [t for t, status in run["tools"].items() if status["ok"]]
            raw = [Finding.model_validate(r) for r in io.read_jsonl(directory / "findings.jsonl")
                   if in_product_code(r["file"])]
            for tool in successful:
                own = [f for f in raw if f.tool == tool]
                out[f"S-{tool}"] = rank_S(merge(own, run["merge_line_tol"]))
            if successful:
                S = rank_S(merged)
        else:
            # Historical snapshots may only have merged.jsonl and individual status files.
            statuses = [io.read_json(p) for p in directory.glob("*.status.json")]
            successful = {s["tool"] for s in statuses if s["ok"]} | {t for m in merged for t in m.tools}
            for tool in successful:
                out[f"S-{tool}"] = rank_S(merged, tool)
            if successful or not statuses:
                S = rank_S(merged)
    if S is not None:
        out["S"] = S
    for model in models:
        tri = _read(out_dir(model, "triage", paths) / item_id / f"{side}.jsonl")
        disc = _read(out_dir(model, "discovery", paths) / item_id / f"{side}.jsonl")
        hyb = _read(out_dir(model, "discovery_hybrid", paths) / item_id / f"{side}.jsonl")
        L = rank_L(disc) if disc is not None else None
        Dp = rank_L(hyb) if hyb is not None else L
        ST = rank_ST(S, tri) if (S is not None and tri is not None) else None
        if L is not None:
            out[f"L@{model}"] = L
        if ST is not None:
            out[f"S+T@{model}"] = ST
        if S is not None and L is not None:
            out[f"S+D@{model}"] = rrf([S, L])
        if ST is not None and Dp is not None:
            out[f"S+T+D@{model}"] = rrf([ST, Dp])
    return out
