"""Nuclei adapter: pinned single binary, JSONL output, CWEs from template classification.

Templates are the community repo (run `nuclei -update-templates` once, or point
tools.nuclei.templates_dir at a pinned checkout). info/tech-detection templates are
excluded via the severity filter so FP counts stay meaningful.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from app.sast.cwe_map import cwes_from_strings
from bench.dast.adapters.base import norm_severity, out_path, result, run_cmd
from bench.dast.config import DastBenchConfig, DastFinding, TargetInfo


def parse_line(line: str, tool: str = "nuclei") -> DastFinding | None:
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        return None
    info = row.get("info") or {}
    classification = info.get("classification") or {}
    cwe = cwes_from_strings(classification.get("cwe-id") or classification.get("cwe"))
    req = row.get("request")
    extracted = row.get("extracted-results")
    return DastFinding(
        tool=tool, rule_id=str(row.get("template-id") or row.get("templateID") or "unknown"),
        title=str(info.get("name") or row.get("template-id") or "nuclei finding"),
        severity=norm_severity(info.get("severity")), cwe=cwe,
        url=str(row.get("matched-at") or row.get("matched_at") or row.get("url") or ""),
        method=str(req.get("method") or "GET") if isinstance(req, dict) else "GET",
        parameter=None, evidence="; ".join(map(str, extracted)) if isinstance(extracted, list) else None,
        message=str(info.get("description") or ""),
    )


def run(target: TargetInfo, out_dir: Path, cfg: DastBenchConfig):
    tool = "nuclei"
    spec = cfg.tool(tool)
    started = time.monotonic()
    findings: list[DastFinding] = []
    exe = shutil.which(spec.executable)
    if not exe:
        res = result(tool, target, findings, started=started, cmd=[],
                     meta={"reason": f"{spec.executable} not found on PATH (see docs/DAST-BENCHMARK.md)"})
        return res.model_copy(update={"ok": False, "skipped": True, "reason": res.meta["reason"]}), findings
    raw = out_path(out_dir, tool)
    cmd = [exe, "-u", target.host_url, "-j", "-o", str(raw), "-silent", "-stats",
           "-severity", spec.severity, "-timeout", "10", "-retries", "1",
           "-rl", "150", "-c", "30", "-duc"]
    if spec.templates_dir:
        cmd += ["-t", str(spec.templates_dir)]
    try:
        completed = run_cmd(cmd, timeout=cfg.scan_timeout_s + 120)
    except subprocess.TimeoutExpired as exc:
        return result(tool, target, findings, started=started, cmd=cmd,
                      error=f"nuclei timed out ({exc})"), findings
    if not raw.is_file():
        return result(tool, target, findings, started=started, cmd=cmd, completed=completed,
                      error="nuclei JSONL report not produced"), findings
    for line in raw.read_text(encoding="utf-8", errors="replace").splitlines():
        f = parse_line(line)
        if f and f.url:
            findings.append(f)
    version = run_cmd([exe, "-version"], timeout=30).stdout.strip() if exe else ""
    res = result(tool, target, findings, started=started, cmd=cmd, completed=completed,
                 meta={"version": version, "severity": spec.severity})
    return res, findings
