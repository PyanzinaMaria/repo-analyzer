from __future__ import annotations

from fastapi import APIRouter

from app import __version__
from app.core.config import get_settings, load_yaml_settings
from app.languages.registry import build_registry

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    settings = get_settings()
    yaml_cfg = load_yaml_settings(settings.settings_path)
    registry = build_registry()
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": __version__,
        "enabled_languages": [h.id for h in registry.enabled()],
        "registered_languages": [h.id for h in registry.all()],
        "config_enabled_languages": yaml_cfg.get("enabled_languages", []),
    }
