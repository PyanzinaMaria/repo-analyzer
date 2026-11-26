"""Static code vulnerability metric via Bandit (SAST)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


SEVERITY_RANK = {"UNDEFINED": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def scan_code_vulnerabilities(
    source_dir: Path | str,
    *,
    severity_min: str = "LOW",
) -> dict[str, Any]:
    """Run Bandit on a source tree and return aggregate vulnerability counts.

    Returns a structure suitable for metrics.json. If Bandit is missing or the
    path is invalid, status explains why and counts stay zero.
    """
    root = Path(source_dir).resolve()
    empty = {
        "status": "skipped",
        "tool": "bandit",
        "source_dir": str(root),
        "code_vulnerabilities": 0,
        "by_severity": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNDEFINED": 0},
        "by_test_id": {},
        "issues": [],
    }
    if not root.exists() or not root.is_dir():
        empty["status"] = "missing_source"
        return empty
    if shutil.which("bandit") is None and not _bandit_module_available():
        empty["status"] = "bandit_not_installed"
        return empty

    excludes = ",".join(
        str(root / name)
        for name in (
            ".venv",
            "venv",
            ".git",
            "node_modules",
            "__pycache__",
            ".tox",
            "dist",
            "build",
        )
        if (root / name).exists()
    )
    cmd = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(root),
        "-f",
        "json",
        "-q",
        "--severity-level",
        severity_min.lower(),
    ]
    if excludes:
        cmd.extend(["--exclude", excludes])
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        empty["status"] = "error"
        empty["error"] = str(exc)
        return empty

    # Bandit exits 1 when it finds issues — still valid JSON on stdout.
    raw = proc.stdout.strip() or "{}"
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        empty["status"] = "invalid_output"
        empty["stderr"] = (proc.stderr or "")[:500]
        return empty

    results = payload.get("results") or []
    by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNDEFINED": 0}
    by_test: dict[str, int] = {}
    issues: list[dict[str, Any]] = []
    min_rank = SEVERITY_RANK.get(severity_min.upper(), 1)

    for item in results:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("issue_severity") or "UNDEFINED").upper()
        if SEVERITY_RANK.get(severity, 0) < min_rank:
            continue
        test_id = str(item.get("test_id") or "UNKNOWN")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_test[test_id] = by_test.get(test_id, 0) + 1
        issues.append(
            {
                "test_id": test_id,
                "severity": severity,
                "filename": item.get("filename"),
                "line": item.get("line_number"),
                "issue_text": item.get("issue_text"),
            }
        )

    total = sum(by_severity.values())
    return {
        "status": "ok",
        "tool": "bandit",
        "source_dir": str(root),
        "code_vulnerabilities": total,
        "by_severity": by_severity,
        "by_test_id": dict(sorted(by_test.items())),
        "issues": issues[:200],
    }


def _bandit_module_available() -> bool:
    try:
        import bandit  # noqa: F401

        return True
    except ImportError:
        return False
