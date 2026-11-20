"""Page routes: index (submission form), scan status, artifact viewers."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.core.config import Settings, get_settings
from app.services import registry
from app.ui.engine import Form

router = APIRouter(tags=["pages"])

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))
templates.env.globals["t"] = lambda key, **kw: get_settings().translate(key, **kw)


def human_size(n: int) -> str:
    value = float(n)
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if value < 1024 or unit == "ГБ":
            return f"{int(value)} {unit}" if unit == "Б" else f"{value:.0f} {unit}"
        value /= 1024
    return f"{n} Б"


def _base_context(request: Request, settings: Settings) -> dict:
    return {
        "request": request,
        "app_title": settings.app.title,
        "settings": settings,
        "human_size": human_size,
    }


def render_index(request: Request, values: dict | None = None, errors: dict | None = None) -> HTMLResponse:
    settings = get_settings()
    form = Form(settings)
    if values is None:
        values = form.default_values()
    ctx = _base_context(request, settings)
    ctx.update({
        "page_title": settings.translate("form.title"),
        "form_spec": form.spec,
        "values": values,
        "errors": errors or {},
        "rules": {
            "max_upload": human_size(settings.upload.max_upload_bytes),
            "max_unpacked": human_size(settings.upload.max_unpacked_bytes),
            "max_file": human_size(settings.upload.max_file_bytes),
            "max_files": settings.upload.max_files,
        },
    })
    return templates.TemplateResponse(request, "pages/index.html", ctx)


@router.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return render_index(request)


def _require_scan(request: Request, scan_id: str) -> dict:
    settings = get_settings()
    status = registry.scan_status(settings, scan_id)
    if status is None:
        raise HTTPException(status_code=404, detail="not_found")
    return status


def _scan_context(request: Request, scan_id: str) -> dict:
    settings = get_settings()
    status = _require_scan(request, scan_id)
    ctx = _base_context(request, settings)
    stage_labels = {s: settings.translate(f"scan.stages.{s}") for s in settings.reports.stages}
    complete = all(s["state"] in {"ok", "fail"} for s in status["stages"])
    ctx.update({
        "page_title": settings.translate("scan.title"),
        "status": status,
        "stage_labels": stage_labels,
        "artifact_specs": {a.name: a for a in settings.reports.artifacts},
        "complete": complete,
    })
    return ctx


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
def scan_page(request: Request, scan_id: str) -> HTMLResponse:
    ctx = _scan_context(request, scan_id)
    return templates.TemplateResponse(request, "pages/scan.html", ctx)


@router.get("/scan/{scan_id}/body", response_class=HTMLResponse)
def scan_body(request: Request, scan_id: str) -> HTMLResponse:
    """HTMX polling fragment: status list plus results when ready."""
    ctx = _scan_context(request, scan_id)
    return templates.TemplateResponse(request, "components/scan_body.html", ctx)


@router.get("/scan/{scan_id}/view/{name}", response_class=HTMLResponse)
def view_artifact(request: Request, scan_id: str, name: str) -> HTMLResponse:
    """Framed, sandboxed viewer for an HTML artifact."""
    settings = get_settings()
    _require_scan(request, scan_id)
    spec = settings.reports.artifact(name)
    if spec is None or spec.viewer != "framed":
        raise HTTPException(status_code=404, detail="unknown_artifact")
    ctx = _base_context(request, settings)
    ctx.update({
        "page_title": settings.translate(spec.label_key),
        "artifact_url": f"/api/scans/{scan_id}/artifacts/{spec.name}",
        "back_url": f"/scan/{scan_id}",
        "back_label_key": "artifacts.back",
    })
    return templates.TemplateResponse(request, "pages/viewer.html", ctx)


def run_cleanup(settings: Settings) -> None:
    registry.cleanup_expired(settings)


__all__ = ["router", "render_index", "run_cleanup"]
