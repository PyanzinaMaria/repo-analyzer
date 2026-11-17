from __future__ import annotations

import logging
from typing import Any

import httpx

from app.ai.config import AiSettings
from app.ai.prompts import REPAIR_PROMPT, SYSTEM_PROMPT

logger = logging.getLogger(__name__)


class AiClientError(RuntimeError):
    pass


class OpenAICompatibleClient:
    def __init__(self, settings: AiSettings, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = settings
        self._transport = transport

    def _headers(self) -> dict[str, str]:
        if not self.settings.api_key:
            raise AiClientError("AI_API_KEY is missing")
        return {
            "Authorization": f"Bearer {self.settings.api_key}",
            "Content-Type": "application/json",
        }

    def chat_json(self, user_prompt: str, *, repair: bool = False) -> str:
        messages: list[dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
        if repair:
            messages.append({"role": "user", "content": REPAIR_PROMPT})

        body: dict[str, Any] = {
            "model": self.settings.model,
            "temperature": 0.1,
            "messages": messages,
            "response_format": {"type": "json_object"},
        }
        url = f"{self.settings.base_url}/chat/completions"
        try:
            with httpx.Client(
                timeout=self.settings.timeout_seconds,
                transport=self._transport,
            ) as client:
                response = client.post(url, headers=self._headers(), json=body)
        except httpx.HTTPError as exc:
            raise AiClientError(f"AI HTTP request failed: {exc}") from exc

        if response.status_code >= 400:
            raise AiClientError(
                f"AI API error {response.status_code}: {response.text[:500]}"
            )

        try:
            data = response.json()
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise AiClientError(f"Unexpected AI response shape: {exc}") from exc

        if not isinstance(content, str) or not content.strip():
            raise AiClientError("Empty AI response content")
        return content
