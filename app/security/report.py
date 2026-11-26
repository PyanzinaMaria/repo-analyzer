from __future__ import annotations

"""Reports for the security pipeline: Markdown, JSON and SARIF 2.1.0.

SARIF makes the result usable by CI/code-scanning dashboards (the same idea
promptfoo uses for its code scanner), while Markdown/JSON feed the audit
pipeline and the FSTEC draft.
"""

import json
from pathlib import Path
from typing import Any

from app.security.models import SecurityRun, Verdict
from app.security.pipeline import top_risks
from app.security.risk import hypothesis_risk, priority_bucket

_MD = """# Security review + pentest: {repo}

- Цель динамической проверки: `{target}`
- Режим ревью: **{mode}**
- Гипотез: {hypotheses} (подтверждено: {confirmed}, опровергнуто: {refuted},
  неопределённо: {uncertain}, пропущено: {skipped})
- Находок в отчёте: {findings}
- Время: {duration} мс

## Топ рисков (подтверждено динамически)

{risks}

## Подтверждённые находки

{confirmed_list}

## Гипотезы без динамического подтверждения

{unverified}

## Поверхность и источники

- Источники гипотез: {sources}
- Проверок выполнено: {plans} (запросов: {requests})
"""

_RISK_ROW = "| {priority} | {severity} | {class} | {where} | {url} | {risk} |\n"
_CONFIRMED = """### {title} ({severity}, {cwe})
- Файл: `{file}`
- URL: `{url}`
- Payload: `{payload}`
- Уверенность: {confidence} (judge: {judged_by})
- Доказательство: {evidence}

Запрос: `{request}`
Ответ: `{response}`

"""
_UNVERIFIED = "- `{file}` — {title} ({class}), уверенность {confidence}, риск {risk} ({priority}), {status}\n"


def render_markdown(run: SecurityRun) -> str:
    meta = run.meta
    risks = top_risks(run, 10)
    rows = "".join(
        _RISK_ROW.format(priority=r["priority"], severity=r["severity"], **{"class": r["class"]},
                         where=r["file"] or "—", url=r["url"] or "—", risk=r["risk"])
        for r in risks
    ) or "Подтверждённых находок нет.\n"
    confirmed_items = []
    for f in run.findings:
        extra = f.extra or {}
        if f.source != "pentest":
            continue
        confirmed_items.append(_CONFIRMED.format(
            title=f.title, severity=f.severity.value, cwe=f.cwe or "—",
            file=f"{f.file}:{f.line}" if f.file else "—",
            url=extra.get("url") or "—", payload=extra.get("payload") or "",
            confidence=extra.get("confidence", "—"), judged_by=extra.get("judged_by", "rules"),
            evidence=extra.get("evidence") or "—", request=extra.get("request") or "",
            response=(extra.get("response") or "")[:400],
        ))
    by_id = {h.id: h for h in run.hypotheses}
    confirmed_ids = {v.hypothesis_id for v in run.verifications
                     if v.verdict == Verdict.confirmed}
    verdict_by_id = {v.hypothesis_id: v.verdict.value for v in run.verifications}
    unverified = []
    for h in run.hypotheses:
        if h.id in confirmed_ids:
            continue
        status = verdict_by_id.get(h.id, "не проверялась (нет цели)" if not run.verifications
                                   else "не проверялась (бюджет)")
        risk = hypothesis_risk(h)
        unverified.append(_UNVERIFIED.format(
            file=f"{h.file}:{h.line}" if h.file else "—", title=h.title,
            **{"class": h.vuln_class.value}, confidence=h.confidence,
            risk=risk, priority=priority_bucket(risk), status=status))
    return _MD.format(
        repo=run.repo, target=run.target_url or "—", mode=meta.get("mode") or "—",
        hypotheses=meta.get("hypotheses", 0), confirmed=meta.get("confirmed", 0),
        refuted=meta.get("refuted", 0), uncertain=meta.get("uncertain", 0),
        skipped=meta.get("skipped", 0), findings=len(run.findings),
        duration=meta.get("duration_ms", 0), risks=rows,
        confirmed_list="\n".join(confirmed_items) or "Подтверждённых находок нет.\n",
        unverified="".join(unverified) or "Все гипотезы проверены.\n",
        sources=json.dumps(meta.get("sources") or {}, ensure_ascii=False),
        plans=(meta.get("verification") or {}).get("plans", 0),
        requests=(meta.get("verification") or {}).get("requests", 0),
    )


def write_reports(run: SecurityRun, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / "security_review.md"
    js = out_dir / "security_review.json"
    sarif = out_dir / "security_review.sarif"
    md.write_text(render_markdown(run), encoding="utf-8")
    js.write_text(json.dumps({
        "repo": run.repo,
        "target_url": run.target_url,
        "meta": run.meta,
        "hypotheses": [h.model_dump() for h in run.hypotheses],
        "verifications": [v.model_dump() for v in run.verifications],
        "findings": [f.model_dump(mode="json") for f in run.findings],
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    sarif.write_text(json.dumps(to_sarif(run), indent=2, ensure_ascii=False), encoding="utf-8")
    return {"markdown": md, "json": js, "sarif": sarif}


def to_sarif(run: SecurityRun) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for h in run.hypotheses:
        rule_id = f"security/{h.vuln_class.value}"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": h.vuln_class.value,
            "shortDescription": {"text": h.title},
            "properties": {"cwe": h.cwe, "tags": ["security", h.vuln_class.value]},
        })
    for v in run.verifications:
        h = next((x for x in run.hypotheses if x.id == v.hypothesis_id), None)
        if h is None or v.verdict == Verdict.skipped:
            continue
        level = {"confirmed": "error", "uncertain": "warning", "refuted": "note"}.get(
            v.verdict.value, "warning")
        results.append({
            "ruleId": f"security/{h.vuln_class.value}",
            "level": level,
            "message": {"text": f"[{v.verdict.value}] {h.title}: {v.explanation}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": h.file or "."},
                    "region": {"startLine": h.line or 1},
                }
            }],
            "properties": {
                "confidence": v.confidence, "cwe": h.cwe,
                "url": v.url, "payload": v.payload, "judged_by": v.judged_by,
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "FSTEC security pipeline",
                "informationUri": "https://github.com/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
