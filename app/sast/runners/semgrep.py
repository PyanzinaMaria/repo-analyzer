from __future__ import annotations

from pathlib import Path

from app.core.yaml_configs import CONFIG_DIR, SastConfig
from app.sast.runners.base import RunResult, ToolMissing, execute
from app.sast.tools import which

LANGUAGES = {"python", "javascript", "typescript"}


def run(target: Path, language: str, sarif: Path, cfg: SastConfig, workdir: Path) -> RunResult:
    exe = which("semgrep")
    if not exe:
        raise ToolMissing("semgrep")
    tcfg = cfg.tools["semgrep"]
    args = [a.format(config=CONFIG_DIR) for a in tcfg.args[language]]
    cmd = [exe, "scan", *args, "--sarif", "--output", str(sarif),
           "--metrics=off", "--disable-version-check", "--quiet",
           "--timeout", "30", "--max-target-bytes", "1000000", "--jobs", "4"]
    for d in cfg.exclude_dirs:
        cmd += ["--exclude", d]
    cmd.append(".")
    return execute("semgrep", cmd, target, tcfg.timeout_s, sarif)
