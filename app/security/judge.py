from __future__ import annotations

"""LLM-as-judge: reduce false positives of dynamic detectors.

A detector says "the response looks like an SQL error". The judge looks at the
hypothesis, the exact request/payload and a response snippet and decides whether
the observation really confirms the vulnerability (or is a false positive such
as reflected input in an error page, a WAF block page, a generic 500, etc.).

Without an LLM the rules-based verdict is used, so the pipeline degrades
gracefully and never depends on quota.
"""

import json
import logging
from typing import Any

from app.security.config import SecurityConfig
from app.security.llm import SecurityLlm, SecurityLlmError
from app.security.models import (
    Detection,
    ProbePlan,
    Severity,
    Verdict,
    Verification,
    VulnHypothesis,
)

logger = logging.getLogger(__name__)

_SYSTEM = """Ты — независимый AppSec-эксперт, который проверяет результаты
автоматического пентеста (policy v2). Тебе дают гипотезу уязвимости, отправленный
payload и фрагмент ответа сервера.

Реши, подтверждает ли ответ гипотезу:
- confirmed — признаки однозначно указывают на уязвимость (ошибка БД, содержимое
  файла, выполнение команды, редирект на чужой домен, отражение без экранирования);
- refuted — это ложное срабатывание (payload просто отражён, страница-заглушка,
  WAF, общая ошибка без утечки, статичный текст);
- uncertain — данных недостаточно.

Отвечай ТОЛЬКО JSON:
{"verdict": "confirmed|refuted|uncertain", "confidence": 0.0-1.0,
 "severity": "critical|high|medium|low", "explanation": "кратко, по-русски",
 "false_positive_reason": "если refuted"}
"""

_SEV = {"critical": Severity.critical, "high": Severity.high, "medium": Severity.medium,
        "low": Severity.low, "info": Severity.info}


def _rules_verdict(detection: Detection, hypothesis: VulnHypothesis) -> tuple[Verdict, float, str]:
    if not detection.matched:
        return Verdict.refuted, 0.3, "детектор не нашёл признаков уязвимости"
    confidence = detection.confidence
    if detection.kind == "status_change":
        confidence = min(confidence, 0.45)
    verdict = Verdict.confirmed if confidence >= 0.6 else Verdict.uncertain
    return verdict, confidence, detection.evidence or "сработал детектор"


def judge_verification(
    hypothesis: VulnHypothesis,
    plan: ProbePlan,
    verification: Verification,
    detection: Detection,
    cfg: SecurityConfig,
    llm: SecurityLlm | None = None,
) -> Verification:
    """Apply the rules verdict, then optionally ask the LLM to confirm/refute."""
    verdict, confidence, explanation = _rules_verdict(detection, hypothesis)
    verification.verdict = verdict
    verification.confidence = confidence
    verification.explanation = explanation
    verification.judged_by = "rules"

    if not cfg.judge_enabled or llm is None or not llm.available:
        return verification
    # only spend an LLM call when there is something to judge
    if not detection.matched:
        return verification

    user = json.dumps({
        "hypothesis": {
            "class": hypothesis.vuln_class.value, "cwe": hypothesis.cwe,
            "file": hypothesis.file, "line": hypothesis.line,
            "evidence": hypothesis.evidence[:600],
        },
        "probe": {"plugin": plan.plugin, "strategy": plan.strategy,
                  "param": plan.param, "payload": plan.payload},
        "detector": {"kind": detection.kind, "evidence": detection.evidence,
                     "snippet": detection.response_snippet[:1200]},
    }, ensure_ascii=False)
    try:
        answer = llm.chat_json(
            [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": user}],
            max_tokens=500,
        )
    except SecurityLlmError as exc:
        logger.warning("judge LLM failed (%s); keeping rules verdict", exc)
        verification.meta["judge_error"] = str(exc)
        return verification

    raw_verdict = str(answer.get("verdict") or "").lower()
    if raw_verdict not in {v.value for v in Verdict}:
        return verification
    llm_verdict = Verdict(raw_verdict)
    try:
        llm_conf = max(0.0, min(1.0, float(answer.get("confidence", confidence))))
    except (TypeError, ValueError):
        llm_conf = confidence
    severity = _SEV.get(str(answer.get("severity") or "").lower(), verification.severity)

    # merge: a rules-confirmed finding can be refuted by the judge (FP filter),
    # but the judge cannot confirm something the detector did not see.
    if llm_verdict == Verdict.refuted:
        verification.verdict = Verdict.refuted
        verification.confidence = llm_conf
    elif llm_verdict == Verdict.confirmed and verdict == Verdict.confirmed:
        verification.verdict = Verdict.confirmed
        verification.confidence = round((confidence + llm_conf) / 2, 2)
        verification.severity = severity
    elif llm_verdict == Verdict.uncertain:
        # a strong deterministic signal (SQL error, executed marker) is not
        # downgraded just because the judge is unsure about the surrounding HTML
        if confidence >= 0.85:
            verification.verdict = verdict
            verification.confidence = confidence
        else:
            verification.verdict = Verdict.uncertain
            verification.confidence = min(confidence, llm_conf)
    verification.explanation = str(answer.get("explanation") or explanation)[:800]
    verification.meta["judge"] = {
        "verdict": answer.get("verdict"),
        "confidence": answer.get("confidence"),
        "false_positive_reason": answer.get("false_positive_reason"),
    }
    verification.judged_by = "rules+llm"
    return verification
