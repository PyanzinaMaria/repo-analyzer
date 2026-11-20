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

    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        json_mode: bool = False,
        repair_prompt: str | None = None,
    ) -> str:
        """One completion with an explicit system prompt. ``json_mode`` adds
        the json_object response format; document generation (Markdown
        answers) runs without it."""
        messages: list[dict[str, str]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        if repair_prompt:
            messages.append({"role": "user", "content": repair_prompt})

        body: dict[str, Any] = {
            "model": self.settings.model,
            "temperature": 0.1,
            "messages": messages,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        content, finish_reason = self._post(body)
        if not content.strip() and "response_format" in body:
            # Some OpenAI-compatible gateways occasionally answer json_object
            # requests with an empty content; retry once without the format.
            body.pop("response_format")
            content, finish_reason = self._post(body)
        if not content.strip():
            raise AiClientError(
                f"Empty AI response content (finish_reason={finish_reason})"
            )
        return content

    def chat_json(self, user_prompt: str, *, repair: bool = False) -> str:
        return self.chat(
            SYSTEM_PROMPT,
            user_prompt,
            json_mode=True,
            repair_prompt=REPAIR_PROMPT if repair else None,
        )

    def _post(self, body: dict[str, Any]) -> tuple[str, str | None]:
        """Returns (content, finish_reason)."""
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
            choice = data["choices"][0]
            content = choice["message"]["content"]
            finish_reason = choice.get("finish_reason")
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise AiClientError(f"Unexpected AI response shape: {exc}") from exc

        if not isinstance(content, str):
            content = ""
        return content, finish_reason
