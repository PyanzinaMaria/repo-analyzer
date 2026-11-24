"""OWASP OFFAT adapter: fuzzes an OpenAPI spec, so targets without a live spec get a
generated one (bench/dast/openapi.py). Test results map coarsely to CWEs via the
OWASP API Top 10 classes OFFAT checks; URL->test-case matching stays endpoint-based.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from bench.dast.adapters.base import out_path, result, run_cmd
from bench.dast.config import DastBenchConfig, DastFinding, TargetInfo
from bench.dast.openapi import probe_openapi, write_spec

# OFFAT test name fragment -> CWE (OWASP API Top 10 mapping; deliberately coarse).
OFFAT_TEST_CWE: list[tuple[str, list[str]]] = [
    ("bola", ["CWE-639"]),
    ("object level", ["CWE-639"]),
    ("access control", ["CWE-285"]),
    ("unrestricted endpoint", ["CWE-285"]),
    ("unrestricted route", ["CWE-285"]),
    ("authorization", ["CWE-285"]),
    ("authentication", ["CWE-287"]),
    ("mass assignment", ["CWE-915"]),
    ("property", ["CWE-915"]),
    ("restricted property", ["CWE-915"]),
    ("resource consumption", ["CWE-770"]),
    ("rate limit", ["CWE-770"]),
    ("brute force", ["CWE-770"]),
    ("injection", ["CWE-20"]),
    ("fuzzing", ["CWE-20"]),
    ("error message", ["CWE-209"]),
]


def test_cwe(test_name: str) -> list[str]:
    low = (test_name or "").lower()
    for needle, cwes in OFFAT_TEST_CWE:
        if needle in low:
            return cwes
    return []


def _rows(payload) -> list[dict]:
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in ("results", "data", "tests"):
            v = payload.get(key)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
    return []


def _is_hit(row: dict) -> bool:
    for key in ("is_vulnerable", "vulnerable", "success"):
        if key in row:
            return bool(row[key])
    verdict = str(row.get("result") or row.get("status") or "").lower()
    return verdict in ("vulnerable", "hit", "fail", "true")


def _row_url(row: dict) -> str:
    req = row.get("request") if isinstance(row.get("request"), dict) else {}
    return str(row.get("url") or row.get("endpoint") or req.get("url") or req.get("path")
               or row.get("path") or "")


def parse(payload, tool: str = "offat") -> list[DastFinding]:
    findings = []
    for row in _rows(payload):
        name = str(row.get("test_name") or row.get("name") or row.get("test") or "OFFAT test")
        url = _row_url(row)
        if not url:
            continue
        findings.append(DastFinding(
            tool=tool, rule_id=name, title=name, severity="medium", cwe=test_cwe(name),
            url=url, method=str(row.get("method") or "GET"),
            parameter=row.get("param") or row.get("parameter"),
            evidence=json.dumps(row.get("response") or "", default=str)[:500] or None,
            message=name,
        ))
    return findings


def run(target: TargetInfo, out_dir: Path, cfg: DastBenchConfig):
    tool = "offat"
    spec = cfg.tool(tool)
    started = time.monotonic()
    findings: list[DastFinding] = []
    exe = shutil.which(spec.executable)
    if not exe:
        res = result(tool, target, findings, started=started, cmd=[],
                     meta={"reason": f"{spec.executable} not found on PATH (pip install offat)"})
        return res.model_copy(update={"ok": False, "skipped": True, "reason": res.meta["reason"]}), findings

    spec_path = Path(target.spec_path) if target.spec_path else None
    if spec_path is None or not spec_path.is_file():
        doc = probe_openapi(target.host_url)
        if doc is None:
            res = result(tool, target, findings, started=started, cmd=[],
                         meta={"reason": "no OpenAPI spec (target.spec_path unset, live probe empty)"})
            return res.model_copy(update={"ok": False, "skipped": True, "reason": res.meta["reason"]}), findings
        spec_path = write_spec(doc, out_dir / "openapi.json")

    raw = out_path(out_dir, tool)
    report = out_dir / "offat-report.json"
    cmd = [exe, "-f", str(spec_path), "-o", "json", "-r", str(report),
           "--disable-ssl-verification"]
    try:
        completed = run_cmd(cmd, timeout=cfg.scan_timeout_s + 120)
    except subprocess.TimeoutExpired as exc:
        return result(tool, target, findings, started=started, cmd=cmd,
                      error=f"offat timed out ({exc})"), findings
    src = report if report.is_file() else (raw if raw.is_file() else None)
    if src is None:
        return result(tool, target, findings, started=started, cmd=cmd, completed=completed,
                      error="offat JSON report not produced"), findings
    try:
        payload = json.loads(src.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        return result(tool, target, findings, started=started, cmd=cmd, completed=completed,
                      error=f"invalid offat JSON: {exc}"), findings
    findings = parse(payload)
    res = result(tool, target, findings, started=started, cmd=cmd, completed=completed,
                 meta={"spec": str(spec_path)})
    return res, findings
