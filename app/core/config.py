from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "repo-analyzer"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    data_dir: Path = Field(default=ROOT_DIR / "data" / "workspaces")
    settings_path: Path = Field(default=ROOT_DIR / "config" / "settings.yaml")
    templates_dir: Path = Field(default=ROOT_DIR / "templates")
    git_timeout_seconds: int = 120

    # Optional AI module (OpenAI-compatible). Secrets only via env.
    ai_api_key: str | None = Field(default=None, validation_alias="AI_API_KEY")
    ai_enabled: bool | None = Field(default=None, validation_alias="AI_ENABLED")
    ai_base_url: str | None = Field(default=None, validation_alias="AI_BASE_URL")
    ai_model: str | None = Field(default=None, validation_alias="AI_MODEL")
    ai_modes: str | None = Field(default=None, validation_alias="AI_MODES")  # e.g. "triage,discovery"
    # used as AI_API_KEY fallback when the AI base_url points at OpenRouter
    openrouter_api_key: str | None = Field(default=None, validation_alias="OPENROUTER_API_KEY")

    def resolve_paths(self) -> None:
        if not self.data_dir.is_absolute():
            self.data_dir = (ROOT_DIR / self.data_dir).resolve()
        if not self.settings_path.is_absolute():
            self.settings_path = (ROOT_DIR / self.settings_path).resolve()
        if not self.templates_dir.is_absolute():
            self.templates_dir = (ROOT_DIR / self.templates_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)


def load_yaml_settings(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "enabled_languages": ["python"],
            "scan": {"exclude_dirs": [".git", ".venv", "venv", "__pycache__"]},
            "reports": {
                "disclaimer": (
                    "Черновик для личного пользования / подготовки материалов. "
                    "Не является полным сертифицированным комплектом документации "
                    "по требованиям ФСТЭК России."
                )
            },
            "ai": {
                "enabled": False,
                "provider": "openai_compatible",
                "base_url": "https://api.openai.com/v1",
                "model": "gpt-4o-mini",
                "timeout_seconds": 120,
                "max_files": 25,
                "max_file_bytes": 40000,
                "max_findings": 50,
            },
        }
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.resolve_paths()
    return settings
