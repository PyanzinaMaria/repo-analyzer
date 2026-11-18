from __future__ import annotations

from app.models.finding import Finding, Severity
from app.models.report import ScanResult
from app.sandbox.runner import SandboxError
from app.services.scan.dast_merge import merge_dast_via_sandbox


def test_merge_skips_when_sandbox_fails(tmp_path, monkeypatch) -> None:
    sast = ScanResult(
        scan_id="scan1",
        project_id="proj1",
        project_name="demo",
        findings=[
            Finding(
                id="s1",
                title="sast hit",
                description="x",
                severity=Severity.high,
                source="bandit",
                language="python",
            )
        ],
        summary={"total_findings": 1, "by_severity": {"high": 1}, "scan_kind": "sast"},
        meta={"languages": {}, "ai": {}},
    )

    def boom(*args, **kwargs):  # noqa: ANN001
        raise SandboxError("no runnable web target detected")

    monkeypatch.setattr("app.services.scan.dast_merge.sandbox_session", boom)

    merged = merge_dast_via_sandbox(sast, tmp_path)
    assert len(merged.findings) == 1
    assert merged.findings[0].source == "bandit"
    assert merged.meta["sandbox"]["status"] == "skipped"
    assert merged.meta["dast"]["status"] == "skipped"
    assert merged.summary["scan_kind"] == "sast+dast"


def test_merge_appends_dast_findings(tmp_path, monkeypatch) -> None:
    sast = ScanResult(
        scan_id="scan2",
        project_id="proj1",
        project_name="demo",
        findings=[
            Finding(
                id="s1",
                title="sast",
                description="x",
                severity=Severity.low,
                source="bandit",
                language="python",
            )
        ],
        summary={"total_findings": 1, "by_severity": {"low": 1}, "scan_kind": "sast"},
        meta={},
    )

    class FakeSession:
        container_name = "ra-dast-x"
        network = "repo-analyzer-dast"
        host_url = "http://127.0.0.1:5555/"
        network_url = "http://ra-dast-x:5000/"
        meta = {"method": "heuristic", "image": "img"}

    class CM:
        def __enter__(self):
            return FakeSession()

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(
        "app.services.scan.dast_merge.sandbox_session",
        lambda *a, **k: CM(),
    )

    class FakeDast:
        def run_to_result(self, body, scan_id=None, **kwargs):  # noqa: ANN001
            return ScanResult(
                scan_id=scan_id or "x",
                project_id="dast-x",
                project_name="t",
                findings=[
                    Finding(
                        id="d1",
                        title="missing header",
                        description="y",
                        severity=Severity.medium,
                        source="dast-preflight",
                        language="python",
                    )
                ],
                summary={"total_findings": 1, "scan_kind": "dast"},
                meta={"dast": {"status": "ok", "target_url": str(body.target_url)}},
            )

    monkeypatch.setattr("app.services.scan.dast_merge.DastOrchestrator", lambda **k: FakeDast())

    merged = merge_dast_via_sandbox(sast, tmp_path)
    assert len(merged.findings) == 2
    assert merged.summary["dast_findings"] == 1
    assert merged.meta["dast"]["status"] == "ok"
    assert merged.meta["sandbox"]["status"] == "ok"
