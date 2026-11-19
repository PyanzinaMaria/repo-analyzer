from __future__ import annotations

import shutil
import time
from pathlib import Path

from app.core.yaml_configs import SastConfig
from app.sast.runners.base import RunResult, ToolMissing, execute, run_cmd
from app.sast.tools import which

LANGUAGES = {"python", "javascript", "typescript"}
CODEQL_LANG = {"python": "python", "javascript": "javascript", "typescript": "javascript"}


def run(target: Path, language: str, sarif: Path, cfg: SastConfig, workdir: Path) -> RunResult:
    exe = which("codeql")
    if not exe:
        raise ToolMissing("codeql")
    tcfg = cfg.tools["codeql"]
    db = workdir / f"codeql-db-{CODEQL_LANG[language]}"
    if db.exists():
        shutil.rmtree(db, ignore_errors=True)
    db.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()
    create = [exe, "database", "create", str(db), f"--language={CODEQL_LANG[language]}",
              f"--source-root={target}", "--overwrite", "--threads=0", "--ram=6000"]
    try:
        rc, out, err = run_cmd(create, target, tcfg.timeout_s)
    except TimeoutError as e:
        shutil.rmtree(db, ignore_errors=True)
        return RunResult(tool="codeql", ok=False, error=f"create: {e}", cmd=create,
                         seconds=time.monotonic() - t0)
    if rc != 0:
        shutil.rmtree(db, ignore_errors=True)
        return RunResult(tool="codeql", ok=False, error=f"create rc={rc}: {(err or out)[-2000:]}",
                         cmd=create, seconds=time.monotonic() - t0, returncode=rc)
    remaining = max(60, tcfg.timeout_s - int(time.monotonic() - t0))
    analyze = [exe, "database", "analyze", str(db), *tcfg.args[language],
               "--format=sarif-latest", f"--output={sarif}", "--threads=0", "--ram=6000",
               "--sarif-add-snippets"]
    res = execute("codeql", analyze, target, remaining, sarif, ok_codes=(0,))
    res.seconds = time.monotonic() - t0
    res.cmd = create + ["&&"] + analyze
    shutil.rmtree(db, ignore_errors=True)
    return res
