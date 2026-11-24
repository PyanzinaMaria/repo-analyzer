"""Shared adapter plumbing: subprocess/docker helpers and tolerant JSON parsing.

Adapter contract — each module under bench/dast/adapters/ exposes:

    run(target: TargetInfo, out_dir: Path, cfg: DastBenchConfig) -> tuple[DastToolResult, list[DastFinding]]

`run` never raises: problems become skipped/failed results with a reason, mirroring the
soft-fail conventions of app/dast and app/sast/runners. Raw tool output is written to
out_dir/<tool>.json; the orchestrator persists status and normalized findings.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterator

from app.dast.normalize import zap_risk_to_severity
from bench.dast.config import DastBenchConfig, DastFinding, DastToolResult, TargetInfo


def which_docker() -> str | None:
    return shutil.which("docker")


def run_cmd(cmd: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    """subprocess.run with a timeout that reliably kills the process tree.

    On Windows a plain kill() of docker.exe leaves the pipes open (the container keeps
    running daemon-side and the docker CLI's console handles survive), which hangs the
    follow-up communicate() forever. taskkill /T /F takes down the whole tree instead.
    """
    if os.name != "nt":
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace",
                            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    try:
        out, err = proc.communicate(timeout=timeout)
        return subprocess.CompletedProcess(cmd, proc.returncode, out, err)
    except subprocess.TimeoutExpired:
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/F", "/T"], capture_output=True)
        try:
            out, err = proc.communicate(timeout=120)
        except (subprocess.TimeoutExpired, ValueError):
            out, err = "", ""
        return subprocess.CompletedProcess(cmd, 124, out, err)


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
