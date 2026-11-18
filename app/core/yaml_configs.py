"""Typed YAML configs of the analysis pipeline: config/sast.yaml (tools, code scope),
config/sinks.yaml (dangerous-call catalog) and config/models.yaml (LLM backends for research runs).

The service settings (`config/settings.yaml`, env) live in app/core/config.py; this module only
describes the analyzer toolchain so that both the server and the research CLI (`bench`) share it.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "config"

Language = Literal["python", "javascript", "typescript"]
FAMILY = {"python": "python", "javascript": "javascript", "typescript": "javascript"}


# --------------------------------------------------------------------------- sast


class ToolConfig(BaseModel):
    enabled: bool = True
    timeout_s: int = 1200
    args: dict[str, list[str]] = Field(default_factory=dict)  # per language


class SastConfig(BaseModel):
    merge_line_tol: int = 3
    tools: dict[str, ToolConfig]
    tool_paths: dict[str, str] = Field(default_factory=dict)
    exclude_dirs: list[str] = Field(default_factory=list)
    # product-code scope: shared by SAST post-filtering, the code index and the benchmark's ground truth
    path_excludes: list[str] = Field(default_factory=list)
    source_extensions: dict[str, list[str]] = Field(default_factory=dict)

    def family_extensions(self, language: str) -> list[str]:
        if FAMILY.get(language, language) == "python":
            return self.source_extensions.get("python", [".py"])
        return self.source_extensions.get("javascript", []) + self.source_extensions.get("typescript", [])


# --------------------------------------------------------------------------- llm


class ModelSpec(BaseModel):
    id: str
    backend: str = "openrouter"
    role: str = "open"
    params: dict = Field(default_factory=dict)
    # extra max_tokens for reasoning models (hidden reasoning tokens count against max_tokens)
    reasoning_headroom: int = 0


class BackendSpec(BaseModel):
    base_url: str
    api_key_env: str | None = None
    api_key: str | None = Field(default=None, exclude=True, repr=False)  # set in code (server settings), never in YAML
    max_concurrency: int = 2
    requests_per_minute: int | None = None
    requests_per_day: int | None = None


class ModelsConfig(BaseModel):
    budget_usd: float = 0.0
    backends: dict[str, BackendSpec]
    models: list[ModelSpec] = Field(default_factory=list)


# --------------------------------------------------------------------------- loading


def _load(path: Path | str, model: type[BaseModel]):
    p = Path(path)
    if not p.is_absolute() and not p.exists():
        p = REPO_ROOT / p
    with open(p, encoding="utf-8") as fh:
        return model.model_validate(yaml.safe_load(fh) or {})


def load_sast_config(path: Path | str = CONFIG_DIR / "sast.yaml") -> SastConfig:
    return _load(path, SastConfig)


def load_models_config(path: Path | str = CONFIG_DIR / "models.yaml") -> ModelsConfig:
    return _load(path, ModelsConfig)


# --------------------------------------------------------------------------- product-code scope


def compile_excludes(patterns: list[str]) -> list[re.Pattern]:
    return [re.compile(p) for p in patterns]


def in_scope(path: str, extensions: list[str], excludes: list[re.Pattern]) -> bool:
    p = path.replace("\\", "/")
    if not any(p.lower().endswith(e) for e in extensions):
        return False
    return not any(rx.search(p) for rx in excludes)


@lru_cache(maxsize=1)
def _default_excludes() -> tuple[re.Pattern, ...]:
    return tuple(compile_excludes(load_sast_config().path_excludes))


def in_product_code(path: str) -> bool:
    """False for tests, benchmarks, examples, docs, vendored/minified code."""
    return not any(rx.search(path.replace("\\", "/")) for rx in _default_excludes())
