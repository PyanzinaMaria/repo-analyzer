"""OWASP ZAP adapter: full scan (spider + active scan) in the official docker image.

The bench runs on the host, so the report travels through a plain bind mount.
ZAP joins the shared docker network and hits the container-DNS URL; the report
JSON is re-parsed with the same alert extraction the product DAST pipeline uses.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from app.dast.normalize import zap_risk_to_severity
from app.dast.zap_baseline import _extract_alerts
from bench.dast.adapters.base import out_path, result, run_cmd, which_docker
from bench.dast.config import DastBenchConfig, DastFinding, TargetInfo


def _instance_findings(alert: dict, tool: str) -> list[DastFinding]:
    plugin_id = str(alert.get("pluginid") or alert.get("pluginId") or alert.get("alertRef") or "unknown")
    name = str(alert.get("name") or alert.get("alert") or f"ZAP alert {plugin_id}")
    cwe_raw = alert.get("cweid") or alert.get("cwe")
    cwe = []
    if cwe_raw not in (None, "", "0", 0, "-1", -1):
        cwe = [f"CWE-{int(cwe_raw)}"]
    instances = [i for i in (alert.get("instances") or []) if isinstance(i, dict)] or [
        {"uri": alert.get("url") or alert.get("uri"), "method": alert.get("method") or "GET",
         "param": alert.get("param"), "evidence": alert.get("evidence"), "attack": alert.get("attack")}
    ]
    out = []
    for inst in instances:
        out.append(DastFinding(
            tool=tool, rule_id=plugin_id, title=name,
            severity=zap_risk_to_severity(alert.get("riskcode", alert.get("risk"))).value,
            cwe=cwe, url=str(inst.get("uri") or inst.get("url") or ""),
            method=str(inst.get("method") or "GET"),
            parameter=inst.get("param"), evidence=inst.get("evidence") or alert.get("evidence"),
            message=name,
        ))
    return out


def run(target: TargetInfo, out_dir: Path, cfg: DastBenchConfig):
    tool = "zap"
    spec = cfg.tool(tool)
    started = time.monotonic()
    findings: list[DastFinding] = []
    docker = which_docker()
    if not docker:
        meta = {"reason": "docker not found on PATH"}
        return result(tool, target, findings, started=started, cmd=[], error="", meta=meta).model_copy(
            update={"ok": False, "skipped": True, "reason": meta["reason"]}), findings
    raw = out_path(out_dir, tool)
    cmd = [docker, "run", "--rm", "--network", target.network,
           "-v", f"{out_dir.resolve()}:/zap/wrk:rw", spec.image,
           "zap-full-scan.py", "-t", target.scan_url, "-J", raw.name, "-I",
           "-T", str(spec.time_limit_m)]
    try:
        completed = run_cmd(cmd, timeout=cfg.scan_timeout_s + 300)
    except subprocess.TimeoutExpired as exc:
        return result(tool, target, findings, started=started, cmd=cmd,
                      error=f"zap timed out after {cfg.scan_timeout_s + 300}s ({exc})"), findings
    if not raw.is_file():
        return result(tool, target, findings, started=started, cmd=cmd, completed=completed,
                      error="zap JSON report not produced"), findings
    try:
        alerts = _extract_alerts(json.loads(raw.read_text(encoding="utf-8")))
    except json.JSONDecodeError as exc:
        return result(tool, target, findings, started=started, cmd=cmd, completed=completed,
                      error=f"invalid zap JSON: {exc}"), findings
    for alert in alerts:
        findings.extend(_instance_findings(alert, tool))
    res = result(tool, target, findings, started=started, cmd=cmd, completed=completed,
                 meta={"alerts": len(alerts), "image": spec.image, "scan_url": target.scan_url})
    return res, findings
