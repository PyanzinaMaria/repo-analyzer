from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.api.deps import get_scan_orchestrator, get_store
from app.models.project import ScanInfo
from app.models.report import ScanResult

router = APIRouter(prefix="/api/v1/projects/{project_id}/scans", tags=["scans"])


@router.get("", response_model=list[ScanInfo])
def list_scans(project_id: str) -> list[ScanInfo]:
    if get_store().get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return get_store().list_scans(project_id)


@router.post("", response_model=ScanInfo, status_code=201)
def start_scan(project_id: str) -> ScanInfo:
    if get_store().get_project(project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    try:
        return get_scan_orchestrator().start_scan(project_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/{scan_id}", response_model=ScanInfo)
def get_scan(project_id: str, scan_id: str) -> ScanInfo:
    scan = get_store().get_scan(project_id, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/result", response_model=ScanResult)
def get_scan_result(project_id: str, scan_id: str) -> ScanResult:
    result = get_store().get_result(project_id, scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan result not found")
    return result
