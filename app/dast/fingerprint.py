from __future__ import annotations

from typing import Any


def build_fingerprint(
    *,
    url: str,
    status_code: int | None,
    headers: dict[str, str],
    body_sample: str,
    final_url: str | None = None,
) -> dict[str, Any]:
    """Normalize HTTP response signals for language detect_runtime hooks."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    server = lower_headers.get("server", "")
    powered = lower_headers.get("x-powered-by", "")
    body_l = body_sample.lower()
    hints: list[str] = []

    blob = f"{server} {powered} {body_l}"
    checks = {
        "fastapi": ("fastapi", "openapi", "/docs", "swagger-ui"),
        "uvicorn": ("uvicorn",),
        "flask": ("flask", "werkzeug"),
        "django": ("django", "csrftoken", "csrfmiddlewaretoken"),
        "express": ("express",),
        "aspnet": ("asp.net", "x-aspnet-version", "kestrel"),
    }
    for hint, needles in checks.items():
        if any(n in blob for n in needles):
            hints.append(hint)

    return {
        "url": url,
        "final_url": final_url or url,
        "status_code": status_code,
        "server": server,
        "powered_by": powered,
        "headers": lower_headers,
        "body_sample": body_sample[:2000],
        "hints": sorted(set(hints)),
    }
