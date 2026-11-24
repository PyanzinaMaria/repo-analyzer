"""Config-driven CLI adapters. All subprocess arguments are passed as separate tokens."""
from __future__ import annotations

import re
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from app.core import io
from app.core.yaml_configs import CONFIG_DIR, SastConfig
from app.sast.runners.base import RunResult, ToolMissing, run_cmd
from app.sast.tools import which


def _executable(name: str) -> str:
    path = which(name)
    if path is None:
        raise ToolMissing(name)
    return path


def _graudit(text: str, database: str) -> dict:
    """Parse graudit's `file:line:message` lines; drop pipeline artifacts (banners, separators,
    "Binary file ... matches", chunks of multi-megabyte lines split by graudit's sed)."""
    results = []
    for line in text.splitlines():
        if not line or set(line) == {"#"}:
            continue
        match = re.fullmatch(r"(.+?):(\d+):(.*)", line)
        if not match:
            continue
        file, number, message = match.groups()
        results.append({"ruleId": database, "message": {"text": message.strip()},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": file},
                                                           "region": {"startLine": int(number)}}}]})
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "graudit"}}, "results": results}]}


def run(tool: str, target: Path, language: str, sarif: Path, cfg: SastConfig) -> RunResult:
    spec = cfg.tools[tool]
    exe = _executable(spec.executable or tool)
    inputs = []
    for pattern in spec.inputs:
        inputs = sorted(str(p) for p in target.glob(pattern) if p.is_file()
                        and not set(p.relative_to(target).parts).intersection(cfg.exclude_dirs))
        if inputs:
            break
    if spec.inputs and not inputs:
        return RunResult(tool=tool, ok=False, reason="input_missing", error=f"No input matching {spec.inputs}")
    started = monotonic()
    res = RunResult(tool=tool, ok=False)
    with TemporaryDirectory(dir=sarif.parent) as tmp:
        # tool_paths are exposed as {name} placeholders so configs can reference
        # auxiliary binaries (e.g. a SpotBugs plugin) resolved per machine.
        values = {"root": target, "work": tmp, "report": sarif, "config": CONFIG_DIR, **cfg.tool_paths}
        # Some launchers (e.g. the joern .bat wrapper) split cmd-line args on "=", so
        # script inputs are handed over through the environment instead of --param.
        env = {k: v.format_map(values) for k, v in spec.env.items()}
        args = spec.args.get(language, [])
        def expand(tokens: list[str]) -> list[str]:
            out = []
            for t in tokens:
                if t == "{inputs}":
                    out.extend(inputs)
                elif t == "{argfile:inputs}":
                    # Windows command lines are limited to ~32k chars; javac and friends take @file lists.
                    # Forward slashes: javac argfiles treat "\r" in "D:\repo" as an escape.
                    f = Path(tmp) / "inputs.txt"
                    f.write_text("\n".join(f'"{Path(i).as_posix()}"' for i in inputs), encoding="utf-8")
                    out.append("@" + str(f))
                elif t == "{project}":
                    # Several project files: prefer the top-most one deterministically.
                    pick = min(inputs, key=lambda p: (len(Path(p).parts), p))
                    out.append(pick)
                elif t == "{args}":
                    out.extend(a.format_map(values) for a in args)
                else:
                    out.append(t.format_map(values))
            return out

        sarif.unlink(missing_ok=True)
        try:
            if spec.prepare:
                prep, *params = expand(spec.prepare)
                res.cmd = [_executable(prep), *params]
                res.returncode, out, err = run_cmd(res.cmd, target, spec.timeout_s, extra_env=env)
                res.prepare_seconds = monotonic() - started
                if res.returncode:
                    res.reason, res.error = "prepare_error", (err or out)[-2000:] or "Preparation failed"
                    return res
            res.cmd = [exe, *expand(spec.command)]
            res.returncode, out, err = run_cmd(res.cmd, target, max(0, spec.timeout_s - (monotonic() - started)),
                                               extra_env=env)
            if spec.output == "graudit":
                io.atomic_write_text(sarif.with_suffix(".txt"), out)
            if res.returncode not in spec.ok_codes:
                res.error = f"rc={res.returncode}: {(err or out)[-2000:]}"
                return res
            if spec.output == "graudit":
                io.write_json(sarif, _graudit(out, args[-1]))
            if not sarif.is_file():
                raise ValueError("Analyzer produced no SARIF report")
            res.ok, res.sarif = True, str(sarif)
        except TimeoutError as e:
            res.reason, res.error = "timeout", str(e)
        finally:
            res.seconds = monotonic() - started
    return res
