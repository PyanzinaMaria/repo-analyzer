from __future__ import annotations

import uuid
from typing import Any

from app.models.finding import Finding, Severity

_ZAP_RISK_TO_SEVERITY = {
    "0": Severity.info,
    "1": Severity.low,
    "2": Severity.medium,
    "3": Severity.high,
    0: Severity.info,
    1: Severity.low,
    2: Severity.medium,
    3: Severity.high,
    "informational": Severity.info,
    "low": Severity.low,
    "medium": Severity.medium,
    "high": Severity.high,
    "critical": Severity.critical,
}


def zap_risk_to_severity(risk: Any) -> Severity:
    if risk is None:
        return Severity.unknown
    key = risk if isinstance(risk, int) else str(risk).strip().lower()
    return _ZAP_RISK_TO_SEVERITY.get(key, Severity.unknown)


def normalize_zap_alerts(
    alerts: list[dict[str, Any]],
    *,
    language: str = "http",
) -> list[Finding]:
    """Convert ZAP baseline/JSON alert objects into Finding models."""
    findings: list[Finding] = []
    for alert in alerts:
        plugin_id = str(alert.get("pluginid") or alert.get("pluginId") or alert.get("alertRef") or "unknown")
        name = str(alert.get("name") or alert.get("alert") or f"ZAP alert {plugin_id}")
        desc = str(alert.get("description") or alert.get("desc") or name)
        risk = alert.get("riskcode", alert.get("risk"))
        cwe_raw = alert.get("cweid") or alert.get("cwe")
        cwe = None
        if cwe_raw not in (None, "", "0", 0, "-1", -1):
            cwe = f"CWE-{cwe_raw}" if not str(cwe_raw).upper().startswith("CWE") else str(cwe_raw)

        instances = alert.get("instances") or []
        if not instances:
            instances = [
                {
                    "uri": alert.get("url") or alert.get("uri"),
                    "method": alert.get("method") or "GET",
                    "param": alert.get("param"),
                    "evidence": alert.get("evidence"),
                    "attack": alert.get("attack"),
                }
            ]

        for idx, inst in enumerate(instances):
            uri = str(inst.get("uri") or inst.get("url") or "")
            findings.append(
                Finding(
                    id=f"dast-zap-{plugin_id}-{uuid.uuid4().hex[:8]}-{idx}",
                    title=name,
                    description=desc,
                    severity=zap_risk_to_severity(risk),
                    cwe=cwe,
                    rule_id=plugin_id,
                    source="zap-baseline",
                    language=language,
                    remediation=str(alert.get("solution") or "") or None,
                    extra={
                        "url": uri,
                        "method": inst.get("method") or "GET",
                        "evidence": inst.get("evidence") or alert.get("evidence"),
                        "parameter": inst.get("param") or alert.get("param"),
                        "attack": inst.get("attack") or alert.get("attack"),
                        "plugin_id": plugin_id,
                        "confidence": alert.get("confidence"),
                    },
                )
            )
    return findings
