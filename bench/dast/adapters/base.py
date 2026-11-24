"""Shared adapter plumbing: subprocess/docker helpers and tolerant JSON parsing.

Adapter contract — each module under bench/dast/adapters/ exposes:

    run(target: TargetInfo, out_dir: Path, cfg: DastBenchConfig) -> tuple[DastToolResult, list[DastFinding]]

`run` never raises: problems become skipped/failed results with a reason, mirroring the
soft-fail conventions of app/dast and app/sast/runners. Raw tool output is written to
out_dir/<tool>.json; the orchestrator persists status and normalized findings.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterator

from app.dast.normalize import zap_risk_to_severity
from bench.dast.config import DastBenchConfig, DastFinding, DastToolResult, TargetInfo


def which_docker() -> str | None:
    return shutil.which("docker")


def run_cmd(cmd: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def out_path(out_dir: Path, tool: str) -> Path:
    return out_dir / f"{tool}.json"


def result(tool: str, target: TargetInfo, findings: list[DastFinding], *, started: float,
           cmd: list[str], completed: subprocess.CompletedProcess[str] | None = None,
           error: str = "", meta: dict | None = None) -> DastToolResult:
    import time

    res = DastToolResult(
        tool=tool, target_id=target.target_id, ok=not error, findings=len(findings),
        seconds=round(time.monotonic() - started, 1), cmd=cmd, error=error[:2000],
        meta={"stdout_tail": (completed.stdout or "")[-2000:] if completed else "",
              "stderr_tail": (completed.stderr or "")[-2000:] if completed else "",
              "returncode": completed.returncode if completed else None, **(meta or {})},
    )
    return res


def iter_json_objects(text: str) -> Iterator[dict[str, Any]]:
    """Tolerant decode: some tools emit concatenated JSON objects or trailing log noise."""
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(text):
        while pos < len(text) and text[pos] not in "{[":
            pos += 1
        if pos >= len(text):
            break
        try:
            obj, end = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            pos += 1
            continue
        if isinstance(obj, dict):
            yield obj
        pos = end


def norm_severity(value: Any) -> str:
    """Tool severity strings -> one of critical/high/medium/low/info/unknown."""
    s = str(value or "").strip().lower()
    if s in ("info", "informational"):
        return "info"
    return s if s in ("critical", "high", "medium", "low") else "unknown"


__all__ = ["zap_risk_to_severity", "which_docker", "run_cmd", "out_path", "result",
           "iter_json_objects", "norm_severity", "DastBenchConfig", "DastFinding", "TargetInfo"]
