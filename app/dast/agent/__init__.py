from __future__ import annotations

"""Pentest agent: LLM-driven (or deterministic) DAST stage.

The agent complements the passive ZAP baseline with *active, targeted* checks:
it discovers entry points (links, forms, query parameters), then plans and runs
safe payload probes (SQLi, XSS, path traversal, open redirect, command
injection, missing security headers, error disclosure) and explains the result.

Two modes:
  * ``--no-llm`` — a deterministic plan (no API key, no quota);
  * LLM mode — a free OpenRouter model picks the next tool call from a JSON
    schema, observes the result and decides when to stop. Budgets are enforced
    by the agent, not by the model.

The same tool layer is exposed over MCP (``python -m app.dast.agent.mcp_server``)
so external hosts (Claude Code, Cursor, ...) can drive it.
"""

__all__ = ["__version__"]
__version__ = "0.1.0"
