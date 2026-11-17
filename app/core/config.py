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
        }
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.resolve_paths()
    return settings
