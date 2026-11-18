"""Jinja2 prompt templates with {# SYSTEM #} / {# USER #} sections."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, StrictUndefined

PROMPT_DIR = Path(__file__).parent / "prompt_templates"
_env = Environment(undefined=StrictUndefined, trim_blocks=False, lstrip_blocks=False, keep_trailing_newline=True)


@lru_cache(maxsize=None)
def _split(name: str) -> tuple[str, str]:
    raw = (PROMPT_DIR / f"{name}.md").read_text(encoding="utf-8")
    sys_part, user_part = raw.split("{# USER #}", 1)
    sys_part = sys_part.replace("{# SYSTEM #}", "", 1)
    return sys_part.strip(), user_part.strip()


def render(name: str, **ctx) -> tuple[str, str]:
    sys_t, user_t = _split(name)
    return _env.from_string(sys_t).render(**ctx).strip(), _env.from_string(user_t).render(**ctx).strip()


def prompt_version(name: str) -> str:
    import hashlib

    return hashlib.sha256((PROMPT_DIR / f"{name}.md").read_bytes()).hexdigest()[:8]
