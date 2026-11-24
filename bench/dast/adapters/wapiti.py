"""Wapiti adapter: native scan (pip install wapiti), JSON report, static class->CWE map.

Wapiti leaves TLS verification off by default, so self-signed benchmark targets just work.
Report keys vary between 3.x versions (dict keyed by attack class vs list of objects), the
parser accepts both shapes.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from bench.dast.adapters.base import out_path, result, run_cmd
from bench.dast.config import DastBenchConfig, DastFinding, TargetInfo

# Wapiti attack class -> CWE(s). Keys are matched against lowercase alnum-only names, so
# "SQL Injection", "sql" and "SqlInjection" all hit the same entry.
WAPITI_CWE: dict[str, list[str]] = {
    "exec": ["CWE-78"],
    "sql": ["CWE-89"],
    "blindsql": ["CWE-89"],
    "xss": ["CWE-79"],
    "permanentxss": ["CWE-79"],
    "file": ["CWE-22", "CWE-73"],
    "filehandling": ["CWE-22", "CWE-73"],
    "pathtraversal": ["CWE-22", "CWE-73"],
    "ssrf": ["CWE-918"],
    "redirect": ["CWE-601"],
    "openredirect": ["CWE-601"],
    "crlf": ["CWE-113"],
    "httpresponsesplitting": ["CWE-113"],
    "unserialize": ["CWE-502"],
    "deserialization": ["CWE-502"],
    "xmlentities": ["CWE-611"],
    "xxe": ["CWE-611"],
    "cookieflags": ["CWE-614", "CWE-1004"],
    "httponlycookie": ["CWE-1004"],
    "securecookie": ["CWE-614"],
    "httpheaders": ["CWE-693"],
    "ssl": ["CWE-295"],
    "certificate": ["CWE-295"],
    "weakcrypto": ["CWE-327"],
    "dangerouslyweakcrypto": ["CWE-327"],
    "bruteforce": [],
    "nikto": [],
    "wapp": [],
}


def wapiti_cwe(category: str) -> list[str]:
    key = re.sub(r"[^a-z]", "", (category or "").lower())
    for name, cwes in WAPITI_CWE.items():
        if name and (key == name or name in key):
            return cwes
    return []


def _extract(payload: dict) -> list[tuple[str, dict]]:
    """(category, hit) pairs from either report shape."""
    vulns = payload.get("vulnerabilities") or {}
    if isinstance(vulns, dict):
        return [(cat, hit) for cat, hits in vulns.items() if isinstance(hits, list)
                for hit in hits if isinstance(hit, dict)]
    if isinstance(vulns, list):  # some 3.x builds emit a flat list with a category field
        return [((hit.get("category") or hit.get("type") or "unknown"), hit)
                for hit in vulns if isinstance(hit, dict) and hit.get("type") != "anomaly"]
    return []


def parse(payload: dict, tool: str = "wapiti") -> list[DastFinding]:
    findings = []
    for category, hit in _extract(payload):
        findings.append(DastFinding(
            tool=tool, rule_id=category, title=str(hit.get("description") or category),
            severity="high", cwe=wapiti_cwe(category),
            url=str(hit.get("url") or hit.get("target") or ""),
            method=str(hit.get("method") or "GET"),
            parameter=hit.get("parameter"), evidence=hit.get("info"),
            message=str(hit.get("info") or hit.get("description") or category),
        ))
    return findings


def run(target: TargetInfo, out_dir: Path, cfg: DastBenchConfig):
    tool = "wapiti"
    spec = cfg.tool(tool)
    started = time.monotonic()
    findings: list[DastFinding] = []
    exe = shutil.which(spec.executable)
    if not exe:
        res = result(tool, target, findings, started=started, cmd=[],
                     meta={"reason": f"{spec.executable} not found on PATH (pip install wapiti)"})
        return res.model_copy(update={"ok": False, "skipped": True, "reason": res.meta["reason"]}), findings
    raw = out_path(out_dir, tool)
    # Per-target session dir: wapiti locks its scan DB in ~/.wapiti, so concurrent
    # runs on the same target collide with PermissionError (WinError 32).
    session_dir = out_dir / "_wapiti-session"
    session_dir.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "-u", target.host_url, "-o", str(raw), "-f", "json",
           "-m", spec.modules, "-l", str(spec.level),
           "--store-session", str(session_dir), "--flush-session",
           "--max-scan-time", str(max(60, cfg.scan_timeout_s)), "-v", "1"]
    try:
        completed = run_cmd(cmd, timeout=cfg.scan_timeout_s + 600)
    except subprocess.TimeoutExpired as exc:
        return result(tool, target, findings, started=started, cmd=cmd,
                      error=f"wapiti timed out ({exc})"), findings
    if not raw.is_file():
        return result(tool, target, findings, started=started, cmd=cmd, completed=completed,
                      error="wapiti JSON report not produced"), findings
    try:
        payload = json.loads(raw.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return result(tool, target, findings, started=started, cmd=cmd, completed=completed,
                      error=f"invalid wapiti JSON: {exc}"), findings
    findings = [f for f in parse(payload) if f.url]
    res = result(tool, target, findings, started=started, cmd=cmd, completed=completed,
                 meta={"modules": spec.modules})
    return res, findings
