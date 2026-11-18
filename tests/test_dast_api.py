from __future__ import annotations

from app.models.dast import DastScanInfo, DastScanStatus
from app.models.report import ScanResult


def test_dast_scan_endpoint(client, monkeypatch, tmp_data_dir) -> None:
    fake_info = DastScanInfo(
        id="deadbeef",
        status=DastScanStatus.completed,
        target_url="http://127.0.0.1:8001/",
        enabled_languages=["python"],
        findings_count=1,
        result_path="x",
    )
    fake_result = ScanResult(
        scan_id="deadbeef",
        project_id="dast-deadbeef",
        project_name="127.0.0.1",
        findings=[],
        summary={"total_findings": 0, "by_severity": {}, "scan_kind": "dast"},
        meta={"dast": {"status": "ok", "target_url": "http://127.0.0.1:8001/"}},
    )

    class FakeOrch:
        def start_scan(self, body):  # noqa: ANN001
            return fake_info

    class FakeStore:
        def get_scan(self, scan_id):  # noqa: ANN001
            return fake_info if scan_id == "deadbeef" else None

        def get_result(self, scan_id):  # noqa: ANN001
            return fake_result if scan_id == "deadbeef" else None

        def reports_dir(self, scan_id):  # noqa: ANN001
            path = tmp_data_dir / "dast" / scan_id / "reports"
            path.mkdir(parents=True, exist_ok=True)
            (path / "dast_report.json").write_text("{}", encoding="utf-8")
            (path / "dast_report.md").write_text("# dast\n", encoding="utf-8")
            return path

    monkeypatch.setattr("app.api.routes.dast.get_dast_orchestrator", lambda: FakeOrch())
    monkeypatch.setattr("app.api.routes.dast.get_dast_store", lambda: FakeStore())

    created = client.post(
        "/api/v1/dast/scans",
        json={"target_url": "http://127.0.0.1:8001/"},
    )
    assert created.status_code == 201
    assert created.json()["id"] == "deadbeef"

    got = client.get("/api/v1/dast/scans/deadbeef")
    assert got.status_code == 200
    assert got.json()["status"] == "completed"

    result = client.get("/api/v1/dast/scans/deadbeef/result")
    assert result.status_code == 200
    assert result.json()["meta"]["dast"]["status"] == "ok"

    report = client.get("/api/v1/dast/scans/deadbeef/reports/dast?format=markdown")
    assert report.status_code == 200
    assert "dast" in report.text.lower()
