"""OWASP ZAP adapter: full scan (spider + active scan) in the official docker image.

Budget design (zap-full-scan.py caps are unreliable end-to-end: the script only writes
its JSON at the very end and can hang past the limits, see zaproxy issue #5040):

  - `-m` caps the spider (unbounded by default!), `-T` caps only the passive-scan wait,
    and the active scan cap goes through `-z -config activescan.maxScanDurationInMins`.
  - The ZAP API is exposed on a fixed port and a watchdog polls the wall clock: if the
    script hasn't written its report by the budget, the alerts are exported through the
    API first and only then the container is killed — so a time-capped run still yields
    the findings collected so far.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import httpx

from app.dast.normalize import zap_risk_to_severity
from app.dast.zap_baseline import _extract_alerts
from bench.dast.adapters.base import out_path, run_cmd, which_docker
from bench.dast.config import DastBenchConfig, DastFinding, TargetInfo

API_PORT = 18090  # fixed so the watchdog can reach the ZAP API from the host


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


def _dump_alerts_via_api(pages: int = 40, chunk: int = 2000) -> list[dict] | None:
    """Export every alert through the ZAP API (paginated); None if the API is unreachable."""
    alerts: list[dict] = []
    with httpx.Client(verify=False, timeout=30) as client:
        for page in range(pages):
            r = client.get(f"http://127.0.0.1:{API_PORT}/JSON/core/view/alerts/",
                           params={"start": page * chunk, "count": chunk})
            if r.status_code != 200:
                break
            batch = r.json().get("alerts") or []
            alerts.extend(batch)
            if len(batch) < chunk:
                return alerts
    return alerts or None


def _kill_tree(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/F", "/T"], capture_output=True)
    else:
        proc.kill()


def run(target: TargetInfo, out_dir: Path, cfg: DastBenchConfig):
    tool = "zap"
    spec = cfg.tool(tool)
    started = time.monotonic()
    findings: list[DastFinding] = []
    docker = which_docker()
    if not docker:
        res = result_stub(tool, target, started, "docker not found on PATH",
                          meta={"reason": "docker not found on PATH"})
        return res.model_copy(update={"skipped": True, "reason": res.meta["reason"]}), findings
    raw = out_path(out_dir, tool)
    container = f"zap-bench-{target.target_id}"
    budget_m = max(5, cfg.scan_timeout_s // 60)
    spider_m = min(spec.time_limit_m, max(2, budget_m // 6))
    passive_m = 5
    active_m = max(5, budget_m - spider_m - passive_m)
    wall = cfg.scan_timeout_s + 900
    cmd = [docker, "run", "--rm", "--name", container, "--network", target.network,
           "-p", f"127.0.0.1:{API_PORT}:{API_PORT}",
           "-v", f"{out_dir.resolve()}:/zap/wrk:rw", spec.image,
           "zap-full-scan.py", "-t", target.scan_url, "-J", raw.name, "-I",
           "-P", str(API_PORT),
           "-m", str(spider_m), "-T", str(passive_m),
           "-z", f"-config activescan.maxScanDurationInMins={active_m}"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace")
    timed_out = False
    # Watchdog: give the script the full budget minus a margin to self-finish; otherwise
    # export alerts through the API first (they are lost otherwise) and kill the container.
    margin_s = 120
    while True:
        try:
            rc = proc.wait(timeout=20)
            break
        except subprocess.TimeoutExpired:
            pass
        if raw.is_file():  # script wrote its report; it exits on its own shortly after
            try:
                proc.wait(timeout=90)
                break
            except subprocess.TimeoutExpired:
                break
        elapsed = time.monotonic() - started
        if elapsed > wall - margin_s:
            timed_out = True
            break
    partial = None
    if timed_out or not raw.is_file():
        partial = _dump_alerts_via_api()
        _kill_tree(proc)
        subprocess.run([docker, "rm", "-f", container], capture_output=True, timeout=60)
    completed = subprocess.CompletedProcess(cmd, 124 if timed_out else (proc.returncode or 0),
                                            "", "")
    if raw.is_file():
        src = raw
    elif partial is not None:
        src = out_dir / "zap-partial.json"
        src.write_text(json.dumps({"alerts": partial}), encoding="utf-8")
    else:
        return result_stub(tool, target, started, "zap JSON report not produced",
                           cmd=cmd, meta={"returncode": completed.returncode,
                                          "timed_out": timed_out}), findings
    try:
        alerts = _extract_alerts(json.loads(src.read_text(encoding="utf-8")))
    except json.JSONDecodeError as exc:
        return result_stub(tool, target, started, f"invalid zap JSON: {exc}",
                           cmd=cmd, meta={"returncode": completed.returncode}), findings
    for alert in alerts:
        findings.extend(_instance_findings(alert, tool))
    res = result_stub(tool, target, started, "", cmd=cmd, completed=None,
                      meta={"alerts": len(alerts), "image": spec.image,
                            "scan_url": target.scan_url, "report": src.name,
                            "timed_out": timed_out,
                            "returncode": completed.returncode})
    return res, findings


def result_stub(tool: str, target: TargetInfo, started: float, error: str, *,
                cmd: list[str] | None = None, meta: dict | None = None,
                completed: subprocess.CompletedProcess | None = None):
    from bench.dast.adapters.base import result as mk_result

    res = mk_result(tool, target, [], started=started, cmd=cmd or [],
                    completed=completed, error=error, meta=meta or {})
    return res
