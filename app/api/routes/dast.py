from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

from app.api.deps import get_dast_orchestrator, get_dast_store
from app.models.dast import DastScanCreate, DastScanInfo
from app.models.project import ReportFormat
from app.models.report import ScanResult

router = APIRouter(prefix="/api/v1/dast/scans", tags=["dast"])


@router.post("", response_model=DastScanInfo, status_code=201)
def start_dast_scan(body: DastScanCreate) -> DastScanInfo:
    try:
        return get_dast_orchestrator().start_scan(body)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{scan_id}", response_model=DastScanInfo)
def get_dast_scan(scan_id: str) -> DastScanInfo:
    scan = get_dast_store().get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="DAST scan not found")
    return scan


@router.get("/{scan_id}/result", response_model=ScanResult)
def get_dast_result(scan_id: str) -> ScanResult:
    result = get_dast_store().get_result(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="DAST result not found")
    return result


@router.get("/{scan_id}/reports/dast")
def get_dast_report(scan_id: str, format: ReportFormat = ReportFormat.json):
    store = get_dast_store()
    if store.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail="DAST scan not found")
    reports_dir = store.reports_dir(scan_id)
    if format == ReportFormat.json:
        path = reports_dir / "dast_report.json"
        if not path.is_file():
            raise HTTPException(status_code=404, detail="DAST JSON report not found")
        return FileResponse(path, media_type="application/json", filename="dast_report.json")
    path = reports_dir / "dast_report.md"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="DAST markdown report not found")
    return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown")
