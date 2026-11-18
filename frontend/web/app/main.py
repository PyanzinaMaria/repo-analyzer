"""Application factory for the audit frontend."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api import artifacts, scans
from app.core.config import get_settings
from app.ui import themeing, views


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    for path in (settings.paths.uploads, settings.paths.reports, settings.paths.queue):
        path.mkdir(parents=True, exist_ok=True)
    themeing.ensure_theme_css(settings)
    views.run_cleanup(settings)
    yield


def _error_response(request: Request, message: str, status: int):
    """HTML error box for pages, JSON for API paths."""
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": message}, status_code=status)
    body = (
        f'<p><a href="/">{get_settings().translate("nav.home")}</a></p>'
        f'<div class="error-box">{message}</div>'
    )
    return HTMLResponse(body, status_code=status)


async def _limit_body(request: Request, call_next):
    """Reject oversized declared payloads with a friendly 413.

    Custom middleware sits outside the exception layer, so the response is
    produced here directly instead of raising HTTPException.
    """
    settings = get_settings()
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > settings.app.server.max_body_bytes:
        return _error_response(request, settings.translate("errors.body_too_large"), 413)
    return await call_next(request)


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app.title, lifespan=lifespan)
    app.middleware("http")(_limit_body)

    package_dir = Path(__file__).resolve().parent
    app.mount("/static", StaticFiles(directory=package_dir / "static"), name="static")

    app.include_router(views.router)
    app.include_router(scans.router)
    app.include_router(artifacts.router)

    @app.exception_handler(404)
    async def not_found(request: Request, exc):
        return _error_response(request, settings.translate("errors.not_found"), 404)

    return app


app = create_app()
