from __future__ import annotations

from pathlib import Path

from app.languages.python.scanners.pip_audit import run_pip_audit


def test_pip_audit_finds_cves_without_installing(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text(
        "Flask==0.12.4\nrequests>=2.0\n",
        encoding="utf-8",
    )

    findings = run_pip_audit(root)
    sources = {f.source for f in findings}
    assert "pip-audit" in sources

    vuln_findings = [f for f in findings if f.rule_id != "pip-audit-error"]
    assert vuln_findings, "expected CVE findings for Flask==0.12.4"
    assert all(f.severity.value == "high" for f in vuln_findings)

    info = [f for f in findings if "пропущена" in f.title]
    assert info, "unpinned requests>=2.0 should be reported as skipped"


def test_pip_audit_reports_when_nothing_pinned(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("requests>=2.0\n", encoding="utf-8")

    findings = run_pip_audit(root)
    assert findings
    assert any("нет закреплённых" in f.title for f in findings)
