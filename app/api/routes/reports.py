from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from app.api.deps import get_store
from app.models.project import ReportFormat, ReportKind

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/scans/{scan_id}/reports",
    tags=["reports"],
)


@router.get("/{kind}")
def get_report(
    project_id: str,
    scan_id: str,
    kind: ReportKind,
    format: ReportFormat = ReportFormat.markdown,
):
    store = get_store()
    if store.get_scan(project_id, scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    reports_dir = store.reports_dir(project_id, scan_id)

    if kind == "security" and format == ReportFormat.json:
        path = reports_dir / "security_report.json"
        if not path.exists():
            raise HTTPException(status_code=404, detail="Security JSON report not found")
        return JSONResponse(content=__load_json(path))

    if kind == "security" and format == ReportFormat.markdown:
        path = reports_dir / "security_report.md"
        if not path.exists():
            raise HTTPException(status_code=404, detail="Security markdown report not found")
        return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown")

    if kind == "fstec":
        if format == ReportFormat.json:
            raise HTTPException(status_code=400, detail="FSTEC draft is markdown-only in MVP")
        path = reports_dir / "fstec_draft.md"
        if not path.exists():
            raise HTTPException(status_code=404, detail="FSTEC draft not found")
        return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown")

    if kind == "audit":
        if format == ReportFormat.json:
            raise HTTPException(status_code=400, detail="Audit report is markdown-only; use security?format=json")
        path = reports_dir / "audit_report.md"
        if not path.exists():
            raise HTTPException(status_code=404, detail="Audit report not found")
        return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown")

    raise HTTPException(status_code=400, detail="Unsupported report request")


@router.get("/{kind}/download")
def download_report(
    project_id: str,
    scan_id: str,
    kind: ReportKind,
    format: ReportFormat = ReportFormat.markdown,
):
    store = get_store()
    reports_dir = store.reports_dir(project_id, scan_id)

    mapping = {
        ("security", ReportFormat.json): reports_dir / "security_report.json",
        ("security", ReportFormat.markdown): reports_dir / "security_report.md",
        ("fstec", ReportFormat.markdown): reports_dir / "fstec_draft.md",
        ("audit", ReportFormat.markdown): reports_dir / "audit_report.md",
    }
    path = mapping.get((kind, format))
    if path is None or not path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(path, filename=path.name)


def __load_json(path):
    import json

    return json.loads(path.read_text(encoding="utf-8"))
