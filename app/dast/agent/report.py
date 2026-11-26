from __future__ import annotations

import json
from pathlib import Path

from app.dast.agent.agent import PentestRun

_MD = """# Pentest-агент: отчёт

- Цель: `{target}`
- Режим: **{mode}**
- Запросов: {requests} за {elapsed} с
- Находок: {findings}

## Поверхность атаки

- Страницы: {pages}
- Эндпоинты: {endpoints}

## Находки

{body}
"""

_ITEM = """### {title} ({severity})
- CWE: {cwe}
- URL: {url}
- Payload: `{payload}`
- Уверенность: {confidence}
- Доказательство: {evidence}

Запрос: `{request}`
Ответ: `{response}`

"""


def render_markdown(run: PentestRun) -> str:
    pages = ", ".join(f"`{p}`" for p in run.pages) or "—"
    endpoints = ", ".join(f"`{e['method']} {e['url']}`" for e in run.endpoints[:10]) or "—"
    body = "\n".join(
        _ITEM.format(
            title=f.title, severity=f.severity.value, cwe=f.cwe or "—",
            url=(f.extra or {}).get("url") or "—",
            payload=(f.extra or {}).get("payload") or "",
            confidence=(f.extra or {}).get("confidence") or "—",
            evidence=(f.extra or {}).get("evidence") or "—",
            request=(f.extra or {}).get("request") or "",
            response=(f.extra or {}).get("response") or "",
        )
        for f in run.findings
    ) or "Находок нет.\n"
    return _MD.format(
        target=run.target_url, mode=run.mode,
        requests=run.stats.get("requests", 0), elapsed=run.stats.get("elapsed_seconds", 0),
        findings=len(run.findings), pages=pages, endpoints=endpoints, body=body,
    )


def write_report(run: PentestRun, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / "pentest_report.md"
    js = out_dir / "pentest_report.json"
    md.write_text(render_markdown(run), encoding="utf-8")
    js.write_text(json.dumps({
        "target_url": run.target_url,
        "mode": run.mode,
        "stats": run.stats,
        "pages": run.pages,
        "endpoints": run.endpoints,
        "findings": [f.model_dump(mode="json") for f in run.findings],
        "steps": run.steps,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    return md, js
