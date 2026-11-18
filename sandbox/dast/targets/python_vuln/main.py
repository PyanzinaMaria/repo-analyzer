"""Intentionally vulnerable FastAPI app for DAST sandbox only."""

from __future__ import annotations

from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="DAST sandbox python_vuln", docs_url="/docs", redoc_url="/redoc")


@app.get("/")
def index() -> HTMLResponse:
    # Missing security headers on purpose; permissive CORS via middleware below.
    return HTMLResponse(
        "<html><body><h1>python_vuln</h1>"
        "<p>Sandbox target for repo-analyzer DAST.</p></body></html>"
    )


@app.get("/search")
def search(q: str = "") -> HTMLResponse:
    # Reflected XSS sink for baseline scanners.
    return HTMLResponse(f"<html><body>Results for: {q}</body></html>")


@app.get("/set-cookie")
def set_cookie() -> Response:
    response = Response(content="cookie set", media_type="text/plain")
    # Missing Secure / HttpOnly / SameSite on purpose.
    response.set_cookie("session", "sandbox-session", path="/")
    return response


@app.get("/cors")
def cors() -> JSONResponse:
    return JSONResponse(
        {"ok": True},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    )


@app.middleware("http")
async def insecure_defaults(request, call_next):
    response = await call_next(request)
    # Advertise stack for language fingerprinting.
    response.headers["Server"] = "uvicorn"
    response.headers["X-Powered-By"] = "FastAPI"
    if request.url.path == "/cors":
        return response
    # Broad CORS on most routes.
    response.headers.setdefault("Access-Control-Allow-Origin", "*")
    return response
