"""`python -m bench context build`: code context per benchmark (item, side)."""

from __future__ import annotations

from pathlib import Path

from app.context.build import build_snapshot_context, load_context
from app.context.slicer import Snapshot
from app.core.runlog import RunSummary, log
from bench.build import load_items, snapshot_dir
from bench.config import Paths


def context_dir(item_id: str, side: str, paths: Paths | None = None) -> Path:
    return (paths or Paths()).context / item_id / side


def load_snapshot(item_id: str, side: str, paths: Paths | None = None) -> Snapshot:
    paths = paths or Paths()
    return load_context(snapshot_dir(item_id, side, paths), context_dir(item_id, side, paths))


def build_all(split: str | None, limit: int | None, force: bool, summary: RunSummary) -> None:
    paths = Paths()
    items = load_items(split, paths)[: limit or None]
    for it in items:
        for side in ("vuln", "fixed"):
            root = snapshot_dir(it["id"], side, paths)
            if not root.exists():
                summary.fail(f"{it['id']}/{side}: snapshot missing (run bench checkout)")
                continue
            try:
                s = build_snapshot_context(root, it["language"], context_dir(it["id"], side, paths), force)
                summary.inc("snapshots")
                summary.inc("functions", s["functions"])
                summary.inc("entrypoints", s["entrypoints"])
            except Exception as e:  # noqa: BLE001
                log.warning("%s/%s: context failed: %s", it["id"], side, e)
                summary.fail(f"{it['id']}/{side}: {e}")
