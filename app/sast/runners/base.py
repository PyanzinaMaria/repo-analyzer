"""Shared subprocess handling for analyzer runners."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

from pydantic import BaseModel

from app.sast.tools import tool_env


class RunResult(BaseModel):
    tool: str
    ok: bool
    skipped: bool = False
    reason: str | None = None
    profile: str | None = None
    version: str | None = None
    prepare_seconds: float = 0.0
    sarif: str | None = None
    seconds: float = 0.0
    error: str | None = None
    cmd: list[str] = []
    returncode: int | None = None


class ToolMissing(RuntimeError):
    pass


def run_cmd(cmd: list[str], cwd: Path, timeout: int, extra_env: dict | None = None) -> tuple[int, str, str]:
    """Run a command in its own process group; kill the whole group on timeout."""
    env = tool_env()
    if extra_env:
        env.update(extra_env)
    proc = subprocess.Popen(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, errors="replace", env=env,
                            start_new_session=(os.name != "nt"))
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            proc.kill()
        out, err = proc.communicate()
        raise TimeoutError(f"timed out after {timeout}s") from None
    return proc.returncode, out, err


def execute(tool: str, cmd: list[str], cwd: Path, timeout: int, sarif: Path,
            ok_codes: tuple[int, ...] = (0, 1), extra_env: dict | None = None) -> RunResult:
    sarif.parent.mkdir(parents=True, exist_ok=True)
    if sarif.exists():
        sarif.unlink()
    t0 = time.monotonic()
    try:
        rc, out, err = run_cmd(cmd, cwd, timeout, extra_env)
    except TimeoutError as e:
        return RunResult(tool=tool, ok=False, reason="timeout", error=str(e), cmd=cmd, seconds=time.monotonic() - t0)
    dt = time.monotonic() - t0
    if rc not in ok_codes or not sarif.exists():
        tail = (err or out or "").strip()[-2000:]
        return RunResult(tool=tool, ok=False, error=f"rc={rc}: {tail}", cmd=cmd, seconds=dt, returncode=rc)
    return RunResult(tool=tool, ok=True, sarif=str(sarif), cmd=cmd, seconds=dt, returncode=rc)
