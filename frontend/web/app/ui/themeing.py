"""Emission of theme.yaml tokens into CSS custom properties."""

from __future__ import annotations

from pathlib import Path

from app.core.config import Settings, ThemeConfig

_TOKEN_ALIASES = {"family": "font-family", "size-base": "font-size"}


def render_theme_css(theme: ThemeConfig) -> str:
    lines = [":root {"]
    for group, values in (("color", theme.colors), ("font", theme.font), ("shape", theme.shape)):
        for name, value in values.items():
            var = _TOKEN_ALIASES.get(name, f"{group}-{name}")
            lines.append(f"    --{var}: {value};")
    lines.append("}")
    return "\n".join(lines) + "\n"


def ensure_theme_css(settings: Settings) -> None:
    """Regenerate static/css/theme.css on every startup (idempotent).

    The stylesheet lives inside the app package, so the target is derived
    from this module's location — not from settings.root, whose layout
    changed when the project moved into the monorepo.
    """
    target = Path(__file__).resolve().parents[1] / "static" / "css" / "theme.css"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_theme_css(settings.theme), encoding="utf-8")
