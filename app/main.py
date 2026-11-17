from __future__ import annotations

from fastapi import FastAPI

from app import __version__
from app.api.routes import api_router
from app.core.config import get_settings
from app.core.logging import setup_logging

setup_logging()
settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=__version__,
    description=(
        "Монолитный backend для анализа репозиториев: "
        "ingest (локальный путь / ZIP / GitHub) → модульные language handlers → "
        "отчёт по уязвимостям и черновик документации для ФСТЭК."
    ),
)
app.include_router(api_router)


@app.get("/")
def root() -> dict:
    return {
        "app": settings.app_name,
        "version": __version__,
        "docs": "/docs",
        "health": "/health",
    }


def run() -> None:
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=False,
    )


if __name__ == "__main__":
    run()
