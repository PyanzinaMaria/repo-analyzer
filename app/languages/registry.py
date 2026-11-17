from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from app.core.config import get_settings, load_yaml_settings
from app.languages.base import LanguageHandler
from app.languages.javascript.handler import JavaScriptHandler
from app.languages.python.handler import PythonHandler

logger = logging.getLogger(__name__)


class LanguageRegistry:
    def __init__(self, handlers: Iterable[LanguageHandler] | None = None) -> None:
        settings = get_settings()
        yaml_cfg = load_yaml_settings(settings.settings_path)
        enabled_ids = {str(x).lower() for x in yaml_cfg.get("enabled_languages", ["python"])}

        catalog: list[LanguageHandler] = (
            list(handlers)
            if handlers is not None
            else [
                PythonHandler(enabled=False),
                JavaScriptHandler(enabled=False),
            ]
        )
        for handler in catalog:
            handler.enabled = handler.id in enabled_ids

        self._handlers = {h.id: h for h in catalog}
        logger.info(
            "Language registry ready: %s",
            {hid: h.enabled for hid, h in self._handlers.items()},
        )

    def all(self) -> list[LanguageHandler]:
        return list(self._handlers.values())

    def enabled(self) -> list[LanguageHandler]:
        return [h for h in self._handlers.values() if h.enabled]

    def get(self, language_id: str) -> LanguageHandler | None:
        return self._handlers.get(language_id)

    def detect_present(self, root: Path) -> list[str]:
        present: list[str] = []
        for handler in self.enabled():
            try:
                if handler.detect(root):
                    present.append(handler.id)
            except Exception:  # noqa: BLE001
                logger.exception("detect failed for %s", handler.id)
        return present


def build_registry() -> LanguageRegistry:
    return LanguageRegistry()
