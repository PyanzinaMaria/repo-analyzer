"""DAST scan orchestration: run each tool against each live target, persist status,
raw report and normalized findings per (target, tool) with SAST-style idempotent caching."""

from __future__ import annotations

import time
from pathlib import Path

from app.core import io
from app.core.runlog import RunSummary, log
from bench.config import Paths
from bench.dast.adapters import DAST_TOOLS
from bench.dast.config import DastBenchConfig, DastFinding, TargetInfo


def _cached(status_file: Path, findings_file: Path, force: bool) -> bool:
    if force or not status_file.is_file() or not findings_file.is_file():
        return False
    try:
        st = io.read_json(status_file)
    except (ValueError, OSError):
        return False
    return bool(st.get("ok") or st.get("skipped"))


def scan(kind: str, tools: list[str] | None, cfg: DastBenchConfig, paths: Paths | None = None,
         force: bool = False, summary: RunSummary | None = None) -> None:
    paths = paths or Paths()
    summary = summary or RunSummary(f"dast scan {kind}")
    state_file = paths.dast / "targets.json"
    state = io.read_json(state_file) if state_file.is_file() else {}
    targets = {tid: rec for tid, rec in state.items()
               if rec.get("kind") == kind and rec.get("status") == "up"}
    if not targets:
        raise SystemExit(f"{kind}: no live targets (run `python -m bench dast up {kind}` first)")
    tools = tools or list(DAST_TOOLS)
    unknown = set(tools).difference(DAST_TOOLS)
    if unknown:
        raise SystemExit(f"unknown tools: {', '.join(sorted(unknown))} (available: {', '.join(DAST_TOOLS)})")

    for tid, rec in sorted(targets.items()):
        target = TargetInfo(target_id=tid, kind=kind, host_url=rec["host_url"],
                            scan_url=rec["scan_url"], network=rec.get("network") or cfg.network,
                            spec_path=rec.get("spec_path"))
        out_dir = paths.dast / tid
        out_dir.mkdir(parents=True, exist_ok=True)
        for tool in tools:
            findings_file = out_dir / f"{tool}.findings.jsonl"
            status_file = out_dir / f"{tool}.status.json"
            if _cached(status_file, findings_file, force):
                summary.inc(f"{tool} cached")
                continue
            started = time.monotonic()
            try:
                res, findings = DAST_TOOLS[tool].run(target, out_dir, cfg)
                res = res.model_dump()
            except Exception as exc:  # noqa: BLE001 - adapters soft-fail; this is a last resort
                summary.fail(f"{tid} {tool}: {str(exc)[:150]}")
                res = {"tool": tool, "target_id": tid, "ok": False, "skipped": False,
                       "reason": f"adapter crashed: {str(exc)[:300]}",
                       "seconds": round(time.monotonic() - started, 1), "findings": 0}
                findings = []
            rows = [f.model_dump() if isinstance(f, DastFinding) else dict(f) for f in findings]
            io.write_jsonl(findings_file, rows)
            io.write_json(status_file, res)
            if res.get("skipped"):
                summary.inc(f"{tool} skipped ({(res.get('reason') or '')[:40]})")
            elif res.get("ok"):
                summary.inc(f"{tool} ok")
                log.info("%s %s: %d findings in %.0fs", tid, tool, len(rows), res.get("seconds", 0))
            else:
                summary.fail(f"{tid} {tool}: {(res.get('reason') or res.get('error') or 'failed')[:150]}")


def target_ids(kind: str, paths: Paths | None = None) -> list[str]:
    paths = paths or Paths()
    f = paths.dast / "targets.json"
    state = io.read_json(f) if f.is_file() else {}
    return sorted(tid for tid, rec in state.items()
                  if rec.get("kind") == kind and rec.get("status") == "up")
