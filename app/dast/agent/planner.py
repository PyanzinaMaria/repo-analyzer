from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.dast.agent.config import PentestConfig
from app.dast.agent.tools import AgentState, ToolRegistry, parse_action, tools_prompt

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """Ты — автономный пентестер-агент для DAST-сканирования веб-приложения.
Твоя задача: исследовать цель и найти уязвимости, используя только разрешённые инструменты.

Правила:
- работай только с предоставленной целью (same-origin), не выходи за её пределы;
- сначала собери поверхность атаки (crawl), затем проверяй найденные параметры;
- не делай деструктивных действий: только GET/POST/HEAD и безопасные payload'ы;
- для каждой гипотезы сначала проверь её инструментом, не выдумывай находки;
- когда закончил (или закончился бюджет) — вызови finish.

Доступные инструменты:
{tools}

Отвечай ТОЛЬКО JSON-объектом вида:
{{"tool": "<имя инструмента>", "args": {{...}}, "thought": "<краткое обоснование>"}}
"""


class LlmPlanner:
    """Chooses the next tool call; falls back to a deterministic plan on errors."""

    def __init__(self, cfg: PentestConfig) -> None:
        self.cfg = cfg

    @property
    def available(self) -> bool:
        return bool(self.cfg.llm_enabled and self.cfg.llm_api_key)

    def next_action(self, state: AgentState, history: list[dict[str, Any]]) -> dict[str, Any]:
        if not self.available:
            raise RuntimeError("LLM planner is disabled (no key or llm_enabled=false)")
        payload = {
            "model": self.cfg.llm_model,
            "temperature": 0.0,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT.format(tools=tools_prompt())},
                {"role": "user", "content": self._observation(state, history)},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": 800,
        }
        with httpx.Client(timeout=self.cfg.llm_timeout, trust_env=False) as client:
            resp = client.post(
                f"{self.cfg.llm_base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.cfg.llm_api_key}",
                         "Content-Type": "application/json"},
                json=payload,
            )
        if resp.status_code >= 400:
            raise RuntimeError(f"LLM API {resp.status_code}: {resp.text[:200]}")
        content = resp.json()["choices"][0]["message"]["content"]
        action = parse_action(content)
        action["thought"] = self._thought(content)
        return action

    @staticmethod
    def _thought(raw: str) -> str:
        try:
            data = json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
            return str(data.get("thought") or "")
        except Exception:  # noqa: BLE001
            return ""

    def _observation(self, state: AgentState, history: list[dict[str, Any]]) -> str:
        recent = history[-6:]
        lines = [
            f"Цель: {state.client.base_url}",
            f"Сделано запросов: {state.client.budget.requests}/{self.cfg.max_requests}, "
            f"время {state.client.budget.elapsed:.0f}с из {self.cfg.max_seconds}с",
            f"Страницы: {state.pages or 'ещё не собраны'}",
            f"Эндпоинты: {state.endpoints or 'ещё не собраны'}",
            f"Находок: {len(state.results)}",
        ]
        if recent:
            lines.append("Последние шаги:")
            for step in recent:
                lines.append(f"  {step.get('tool')} {step.get('args')} -> "
                             f"{json.dumps(step.get('result'), ensure_ascii=False)[:300]}")
        lines.append("Какой следующий инструмент вызвать? Верни JSON.")
        return "\n".join(lines)
