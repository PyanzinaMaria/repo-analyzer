"""Run Semgrep with generated rules and normalize its JSON output.

Reuses the analyzer's tool lookup (`app.sast.tools.which`, honoring config/sast.yaml tool_paths) and the
subprocess handling of the SAST runners (UTF-8 env for Windows, process-group kill on timeout).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from app.llmflow.models import Match
from app.sast.runners.base import run_cmd
from app.sast.tools import set_overrides, which

FIELD = re.compile(r"@@(\w+)=(.*?)(?=@@)", re.S)


class SemgrepMissing(RuntimeError):
    pass


class SemgrepFailed(RuntimeError):
    pass


def semgrep_exe() -> str:
    from app.core.yaml_configs import load_sast_config

    set_overrides(load_sast_config().tool_paths)
    exe = which("semgrep")
    if not exe:
        raise SemgrepMissing(
            "semgrep not found: install it into the analyzer venv (`pip install semgrep`; on Windows a native "
            "wheel exists for semgrep>=1.1xx) or set tool_paths.semgrep in config/sast.yaml")
    return exe


def _decode(message: str) -> dict:
    out = {}
    for k, v in FIELD.findall(message + "@@"):
        v = v.strip()
        out[k] = None if v.startswith("$") and re.fullmatch(r"\$[A-Z_][A-Z0-9_]*", v) else v
    return out


def run_rules(target: Path, rules_file: Path, raw_out: Path, excludes: list[str],
              timeout_s: int = 1200, jobs: int = 4) -> tuple[list[Match], list[dict]]:
    """Run one rules file over `target`; returns (matches, semgrep errors)."""
    exe = semgrep_exe()
    cmd = [exe, "scan", "--config", str(rules_file.resolve()), "--json", "--output", str(raw_out.resolve()),
           "--metrics=off", "--disable-version-check", "--quiet", "--no-git-ignore",
           "--timeout", "30", "--max-target-bytes", "1000000", "--jobs", str(jobs)]
    for d in excludes:
        cmd += ["--exclude", d]
    cmd.append(".")
    raw_out.parent.mkdir(parents=True, exist_ok=True)
    if raw_out.exists():
        raw_out.unlink()
    rc, out, err = run_cmd(cmd, target, timeout_s)
    if rc not in (0, 1) or not raw_out.exists():
        raise SemgrepFailed(f"semgrep rc={rc}: {(err or out or '').strip()[-2000:]}")
    data = json.loads(raw_out.read_text(encoding="utf-8"))
    matches = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = dict(extra.get("metadata", {}) or {})
        meta.setdefault("severity", extra.get("severity"))
        msg = extra.get("message", "") or ""
        matches.append(Match(
            rule_id=r["check_id"].rsplit(".llmflow.", 1)[-1] if ".llmflow." in r["check_id"] else r["check_id"],
            family=meta.get("family", "unknown"),
            file=r["path"].replace("\\", "/").removeprefix("./"),
            line=r["start"]["line"], end_line=r["end"]["line"], col=r["start"]["col"],
            meta=meta, fields=_decode(msg), message=msg,
        ))
    errors = [e for e in data.get("errors", []) if e.get("level", "error") == "error"]
    return matches, errors


def run_test(rules_dir: Path, timeout_s: int = 600) -> tuple[int, str]:
    """`semgrep --test` over a directory of rule files + same-named test files."""
    exe = semgrep_exe()
    cmd = [exe, "scan", "--test", "--metrics=off", "--disable-version-check", str(rules_dir.resolve())]
    # semgrep --test runs configs in parallel and they race on creating ~/.semgrep/settings.yml on Windows:
    # point them at a complete settings file, so no process has to write it
    settings = (rules_dir / ".semgrep_settings.yml").resolve()
    settings.write_text("has_shown_metrics_notification: true\n"
                        "anonymous_user_id: 00000000-0000-4000-8000-000000000000\n", encoding="utf-8")
    rc, out, err = run_cmd(cmd, rules_dir, timeout_s, extra_env={"SEMGREP_SETTINGS_FILE": str(settings)})
    text = (out or "") + (err or "")
    if rc == 0 and "produced errors" in text:
        rc = 2                       # semgrep --test exits 0 even when a config could not run
    return rc, text
