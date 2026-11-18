"""Locate external analyzers. Search order: sast.yaml tool_paths, PATH, the running venv, then the
locations used by scripts/setup.sh."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HOME = Path.home()

# Default install locations used by scripts/setup.sh
DEFAULT_LOCATIONS: dict[str, list[Path]] = {
    "semgrep": [HOME / ".venvs/sast/bin/semgrep"],
    "bandit": [HOME / ".venvs/sast/bin/bandit"],
    "node": [HOME / ".local/node/bin/node"],
    "codeql": [HOME / "tools/codeql/codeql"],
}

ESLINT_HOME = Path(os.environ.get("SECBENCH_ESLINT_HOME", str(HOME / ".cache/secbench-eslint")))

_overrides: dict[str, str] = {}


def set_overrides(paths: dict[str, str]) -> None:
    _overrides.update({k: os.path.expanduser(v) for k, v in paths.items()})


def which(name: str) -> str | None:
    if name in _overrides and Path(_overrides[name]).exists():
        return _overrides[name]
    found = shutil.which(name)
    if found:
        return found
    # console scripts of the running interpreter's venv (e.g. bandit from requirements.txt) when the venv
    # is not activated
    for candidate in (Path(sys.executable).parent / name, Path(sys.executable).parent / f"{name}.exe"):
        if candidate.exists():
            return str(candidate)
    for p in DEFAULT_LOCATIONS.get(name, []):
        if p.exists():
            return str(p)
    return None


def eslint_paths() -> tuple[Path, Path, Path] | None:
    """(eslint.js, config, sarif formatter) under ESLINT_HOME, or None if not installed."""
    home = Path(_overrides.get("eslint_home", ESLINT_HOME))
    eslint_js = home / "node_modules/eslint/bin/eslint.js"
    config = home / "eslint.config.mjs"
    formatter = home / "node_modules/@microsoft/eslint-formatter-sarif/sarif.js"
    if eslint_js.exists() and config.exists() and formatter.exists():
        return eslint_js, config, formatter
    return None


def tool_env() -> dict[str, str]:
    """Environment for analyzer subprocesses: make sure node is on PATH."""
    env = dict(os.environ)
    node = which("node")
    if node:
        env["PATH"] = str(Path(node).parent) + os.pathsep + env.get("PATH", "")
    env.setdefault("SEMGREP_SEND_METRICS", "off")
    return env


def _first_line(cmd: list[str]) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=tool_env())
        text = (out.stdout or out.stderr).strip().splitlines()
        return text[0].strip() if text else None
    except Exception:  # noqa: BLE001
        return None


def tool_versions() -> dict[str, str | None]:
    v: dict[str, str | None] = {}
    if p := which("semgrep"):
        v["semgrep"] = _first_line([p, "--version"])
    if p := which("bandit"):
        v["bandit"] = _first_line([p, "--version"])
    if p := which("node"):
        v["node"] = _first_line([p, "--version"])
        if e := eslint_paths():
            v["eslint"] = _first_line([p, str(e[0]), "--version"])
            node_modules = e[0].parents[2]
            for dep in ("eslint-plugin-security", "typescript-eslint", "@microsoft/eslint-formatter-sarif"):
                try:
                    v[dep] = json.loads((node_modules / dep / "package.json").read_text())["version"]
                except Exception:  # noqa: BLE001
                    v[dep] = None
    if p := which("codeql"):
        v["codeql"] = _first_line([p, "version", "--format=terse"])
    return v
