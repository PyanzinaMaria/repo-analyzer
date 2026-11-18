from __future__ import annotations

import threading
from pathlib import Path

from app.core.config import get_settings
from app.models.dast import DastScanInfo, DastScanStatus
from app.models.report import ScanResult


class DastStore:
    """Filesystem store for DAST scans (no repository workspace required)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.settings = get_settings()
        self.root = self.settings.data_dir / "dast"
        self.root.mkdir(parents=True, exist_ok=True)

    def scan_dir(self, scan_id: str) -> Path:
        path = self.root / scan_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _info_path(self, scan_id: str) -> Path:
        return self.scan_dir(scan_id) / "scan.json"

    def _result_path(self, scan_id: str) -> Path:
        return self.scan_dir(scan_id) / "result.json"

    def reports_dir(self, scan_id: str) -> Path:
        path = self.scan_dir(scan_id) / "reports"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def save_scan(self, scan: DastScanInfo) -> DastScanInfo:
        with self._lock:
            path = self._info_path(scan.id)
            path.write_text(scan.model_dump_json(indent=2), encoding="utf-8")
            return scan

    def get_scan(self, scan_id: str) -> DastScanInfo | None:
        path = self._info_path(scan_id)
        if not path.exists():
            return None
        return DastScanInfo.model_validate_json(path.read_text(encoding="utf-8"))

    def save_result(self, result: ScanResult) -> Path:
        path = self._result_path(result.scan_id)
        path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        return path

    def get_result(self, scan_id: str) -> ScanResult | None:
        path = self._result_path(scan_id)
        if not path.exists():
            return None
        return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))

    def mark(
        self,
        scan_id: str,
        status: DastScanStatus,
        *,
        error: str | None = None,
        findings_count: int | None = None,
        result_path: str | None = None,
    ) -> DastScanInfo:
        scan = self.get_scan(scan_id)
        if scan is None:
            raise KeyError(scan_id)
        scan.status = status
        if error is not None:
            scan.error = error
        if findings_count is not None:
            scan.findings_count = findings_count
        if result_path is not None:
            scan.result_path = result_path
        return self.save_scan(scan)
