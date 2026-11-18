"""Run SAST tools on one directory and write SARIF + normalized + merged findings."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from app.core import io
from app.core.yaml_configs import SastConfig
from app.core.runlog import log
from app.sast.normalize import Side, merge, normalize
from app.sast.runners import RUNNERS
from app.sast.runners.base import RunResult, ToolMissing
from app.sast.sarif import parse_sarif


def detect_language(root: Path) -> str:
    counts = {"python": 0, "javascript": 0, "typescript": 0}
    skip = {"node_modules", ".git", ".venv", "venv", "dist", "build"}
    for p in root.rglob("*"):
        if any(part in skip for part in p.parts):
            continue
        if p.suffix == ".py":
            counts["python"] += 1
        elif p.suffix in {".js", ".jsx", ".mjs", ".cjs"}:
            counts["javascript"] += 1
        elif p.suffix in {".ts", ".tsx"}:
            counts["typescript"] += 1
    return max(counts, key=counts.get)


def run_tools_isolated(target: Path, *args, **kwargs) -> dict[str, RunResult]:
    """Run on a temporary copy of `target`.

    Needed for ad-hoc directories inside another git repo (e.g. tests/fixtures): Semgrep applies
    the enclosing repo's ignore rules (its defaults skip `tests/`) and would silently scan nothing.
    """
    skip = shutil.ignore_patterns(".git", "node_modules", ".venv", "venv", "__pycache__")
    with tempfile.TemporaryDirectory(prefix="secaudit-") as tmp:
        copy = Path(tmp) / target.resolve().name
        shutil.copytree(target, copy, ignore=skip, symlinks=True)
        return run_tools(copy, *args, **kwargs)


def run_tools(target: Path, language: str, out_dir: Path, tools: list[str], cfg: SastConfig,
              item_id: str, side: Side, force: bool = False) -> dict[str, RunResult]:
    target = target.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, RunResult] = {}
    for tool in tools:
        runner = RUNNERS[tool]
        tcfg = cfg.tools.get(tool)
        if tcfg is None or not tcfg.enabled or language not in runner.LANGUAGES:
            continue
        status_path = out_dir / f"{tool}.status.json"
        sarif = out_dir / f"{tool}.sarif"
        if not force and status_path.exists():
            prev = RunResult.model_validate(io.read_json(status_path))
            if prev.ok and sarif.exists():
                prev.skipped = True
                results[tool] = prev
                continue
        log.info("%s: %s on %s/%s", item_id, tool, side, language)
        try:
            res = runner.run(target, language, sarif, cfg, out_dir / "work")
        except ToolMissing as e:
            res = RunResult(tool=tool, ok=False, error=f"tool missing: {e}")
        io.write_json(status_path, res)
        results[tool] = res
        if not res.ok:
            log.warning("%s: %s failed: %s", item_id, tool, (res.error or "")[:300])

    raw = []
    for tool, res in results.items():
        if res.ok and res.sarif:
            try:
                raw += parse_sarif(res.sarif, root=target)
            except Exception as e:  # noqa: BLE001
                log.warning("%s: could not parse %s SARIF: %s", item_id, tool, e)
    findings = normalize(raw, item_id, side)
    merged = merge(findings, cfg.merge_line_tol)
    io.write_jsonl(out_dir / "findings.jsonl", findings)
    io.write_jsonl(out_dir / "merged.jsonl", merged)
    work = out_dir / "work"
    if work.exists() and not any(work.iterdir()):
        work.rmdir()
    return results
