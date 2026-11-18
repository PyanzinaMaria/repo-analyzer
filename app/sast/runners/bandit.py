from __future__ import annotations

from pathlib import Path

from app.core.yaml_configs import SastConfig
from app.sast.runners.base import RunResult, ToolMissing, execute
from app.sast.tools import which

LANGUAGES = {"python"}


def run(target: Path, language: str, sarif: Path, cfg: SastConfig, workdir: Path) -> RunResult:
    exe = which("bandit")
    if not exe:
        raise ToolMissing("bandit")
    excludes = ["*/tests/*", "*/test/*"] + [f"*/{d}/*" for d in cfg.exclude_dirs]
    cmd = [exe, "-r", ".", "-f", "sarif", "-o", str(sarif), "-q", "-x", ",".join(excludes)]
    return execute("bandit", cmd, target, cfg.tools["bandit"].timeout_s, sarif)
