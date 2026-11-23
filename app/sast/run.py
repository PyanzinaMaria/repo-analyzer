"""Run SAST tools on one directory and write SARIF + normalized + merged findings."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path

import logging

from app.core import io
from app.core.yaml_configs import CONFIG_DIR, SastConfig, load_sast_config
from app.sast.normalize import Side, merge, normalize
from app.sast.runners import RUNNERS, configured
from app.sast.tools import analyzer_version
from app.sast.runners.base import RunResult, ToolMissing
from app.sast.sarif import parse_sarif

log = logging.getLogger(__name__)


def detect_language(root: Path, cfg: SastConfig | None = None) -> str:
    cfg = cfg or load_sast_config()
    counts = dict.fromkeys(cfg.source_extensions, 0)
    for directory, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in cfg.exclude_dirs]
        for name in files:
            for lang, extensions in cfg.source_extensions.items():
                if Path(name).suffix.lower() in extensions:
                    counts[lang] += 1
    if not any(counts.values()):
        raise ValueError(f"No configured source files under {root}")
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
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, RunResult] = {}
    raw = []
    for tool in tools:
        spec = cfg.tools[tool]
        runner = RUNNERS.get(tool)
        languages = spec.languages if spec.languages is not None else runner.LANGUAGES
        status_path = out_dir / f"{tool}.status.json"
        sarif = out_dir / f"{tool}.sarif"
        res = RunResult(tool=tool, ok=False)
        if not spec.enabled:
            res.reason = "disabled"
        elif language not in languages or (spec.requires and not any(
                any(target.glob(pattern)) for pattern in spec.requires)):
            res.reason = "not_applicable"
        else:
            try:
                version = analyzer_version(tool, spec)
                digest = hashlib.sha256(io.dumps([spec, cfg.exclude_dirs, cfg.tool_paths, language, version]).encode())
                for token in [*spec.command, *spec.prepare, *spec.args.get(language, [])]:
                    if token.startswith("{config}/"):
                        digest.update((CONFIG_DIR / token.removeprefix("{config}/")).read_bytes())
                profile = digest.hexdigest()
                if not force and side != "adhoc" and status_path.exists() and sarif.is_file():
                    prev = RunResult.model_validate(io.read_json(status_path))
                    if prev.ok and prev.profile == profile:
                        res = prev
                        res.skipped = True
                if not res.skipped:
                    if spec.command:
                        res = configured.run(tool, target, language, sarif, cfg)
                    else:
                        res = runner.run(target, language, sarif, cfg, out_dir / "work")
                res.version, res.profile = version, profile
                if res.ok:
                    raw.extend(parse_sarif(sarif, root=target, tool_id=tool))
            except ToolMissing as exc:
                res.reason, res.error = "missing", str(exc)
            except (ValueError, OSError, KeyError, TypeError) as exc:
                res.ok, res.skipped, res.error = False, False, str(exc)
            if not res.ok:
                res.reason = res.reason or "error"
                log.warning("%s/%s %s: %s", item_id, side, tool, res.error)
        io.write_json(status_path, res)
        results[tool] = res

    findings = normalize(raw, item_id, side)
    merged = merge(findings, cfg.merge_line_tol)
    io.write_jsonl(out_dir / "findings.jsonl", findings)
    io.write_jsonl(out_dir / "merged.jsonl", merged)
    io.write_json(out_dir / "runs.json", {"tools": results, "merge_line_tol": cfg.merge_line_tol})
    work = out_dir / "work"
    if work.exists() and not any(work.iterdir()):
        work.rmdir()
    return results
