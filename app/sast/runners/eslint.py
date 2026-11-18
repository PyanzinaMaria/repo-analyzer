from __future__ import annotations

from pathlib import Path

from app.core.yaml_configs import SastConfig
from app.sast.runners.base import RunResult, ToolMissing, execute
from app.sast.tools import eslint_paths, which

LANGUAGES = {"javascript", "typescript"}


def run(target: Path, language: str, sarif: Path, cfg: SastConfig, workdir: Path) -> RunResult:
    node = which("node")
    paths = eslint_paths()
    if not node or not paths:
        raise ToolMissing("eslint (run scripts/setup.sh)")
    eslint_js, config, formatter = paths
    # With -c, ESLint 9 uses the cwd as base path, so run inside the target and pass the
    # formatter by absolute path (package resolution would be relative to the target).
    cmd = [node, str(eslint_js), "-c", str(config), "-f", str(formatter), "-o", str(sarif),
           "--no-warn-ignored", "--no-error-on-unmatched-pattern", "."]
    # rc 1 = lint errors found, 2 = config/crash
    return execute("eslint", cmd, target, cfg.tools["eslint"].timeout_s, sarif,
                   extra_env={"NODE_OPTIONS": "--max-old-space-size=6144"})
