"""Nikto adapter: official docker image (Perl tool, no native Windows setup).

Nikto is a server-level scanner: most items have no CWE and rarely reference a benchmark
test URL, which the eval side reports honestly as non-test findings. Self-signed TLS
targets need the explicit -ssl flag.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from bench.dast.adapters.base import iter_json_objects, norm_severity, out_path, result, run_cmd, which_docker
from bench.dast.config import DastBenchConfig, DastFinding, TargetInfo

# A few Nikto items that carry an identifiable CWE class in their text.
NIKTO_ITEM_CWE: list[tuple[str, list[str]]] = [
    ("/admin", ["CWE-16"]), ("directory indexing", ["CWE-548"]),
    ("backup", ["CWE-530"]), ("xssi", ["CWE-79"]),
    ("trace", ["CWE-16"]), ("cookie", ["CWE-614"]),
]


def _item_cwe(text: str) -> list[str]:
    low = (text or "").lower()
    for needle, cwes in NIKTO_ITEM_CWE:
        if needle in low:
            return cwes
    return []


def parse(payload, tool: str = "nikto") -> list[DastFinding]:
    """Accepts both report shapes: a single host record or the array of host records
    nikto 2.5 emits (`[{"host":..., "vulnerabilities": [...]}]`); item text lives in
    `msg` (2.5) or `item`/`description` (older), and `url` is often a bare path."""
    records = payload if isinstance(payload, list) else [payload]
    findings = []
    for record in records:
        if not isinstance(record, dict):
            continue
        host = str(record.get("host") or record.get("ip") or "")
        port = record.get("port") or ""
        scheme = "https" if record.get("ssl") else "http"
        base = f"{scheme}://{host}:{port}" if host else ""
        for item in record.get("vulnerabilities") or []:
            if not isinstance(item, dict):
                continue
            text = str(item.get("item") or item.get("msg") or item.get("description") or "")
            url = str(item.get("url") or "/")
            if not url.startswith("http"):
                url = base + (url if url.startswith("/") else "/" + url)
            findings.append(DastFinding(
                tool=tool, rule_id=str(item.get("id") or item.get("OSVDBLCV") or "nikto"),
                title=text, severity=norm_severity(item.get("severity")) if item.get("severity") else "low",
                cwe=_item_cwe(text), url=url, method=str(item.get("method") or "GET"),
                parameter=None, evidence=item.get("http") and f"HTTP {item.get('http')}",
                message=text,
            ))
    return findings


def run(target: TargetInfo, out_dir: Path, cfg: DastBenchConfig):
    tool = "nikto"
    spec = cfg.tool(tool)
    started = time.monotonic()
    findings: list[DastFinding] = []
    docker = which_docker()
    if not docker:
        res = result(tool, target, findings, started=started, cmd=[],
                     meta={"reason": "docker not found on PATH"})
        return res.model_copy(update={"ok": False, "skipped": True, "reason": res.meta["reason"]}), findings
    raw = out_path(out_dir, tool)
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [docker, "run", "--rm", "--network", target.network,
           "-v", f"{out_dir.resolve()}:/output", spec.image,
           "-h", target.scan_url, "-o", f"/output/{raw.name}", "-Format", "json",
           "-ask+", "-maxtime", f"{max(1, cfg.scan_timeout_s // 60)}m"]
    if target.scan_url.startswith("https"):
        cmd.append("-ssl")
    try:
        completed = run_cmd(cmd, timeout=cfg.scan_timeout_s + 600)
    except subprocess.TimeoutExpired as exc:
        return result(tool, target, findings, started=started, cmd=cmd,
                      error=f"nikto timed out ({exc})"), findings
    if not raw.is_file():
        return result(tool, target, findings, started=started, cmd=cmd, completed=completed,
                      error="nikto JSON report not produced"), findings
    findings = []
    for payload in iter_json_objects(raw.read_text(encoding="utf-8", errors="replace")):
        findings.extend(f for f in parse(payload) if f.url)
    res = result(tool, target, findings, started=started, cmd=cmd, completed=completed,
                 meta={"image": spec.image})
    return res, findings
