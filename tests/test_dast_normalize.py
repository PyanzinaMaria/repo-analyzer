from __future__ import annotations

import json
from pathlib import Path

from app.dast.normalize import normalize_zap_alerts, zap_risk_to_severity
from app.models.finding import Severity

FIXTURE = Path(__file__).parent / "fixtures" / "dast" / "zap_alerts.json"


def test_zap_risk_mapping() -> None:
    assert zap_risk_to_severity("3") is Severity.high
    assert zap_risk_to_severity("low") is Severity.low
    assert zap_risk_to_severity(None) is Severity.unknown


def test_normalize_zap_fixture_language() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    alerts = payload["site"][0]["alerts"]
    findings = normalize_zap_alerts(alerts, language="python")
    assert len(findings) == 2
    assert all(f.source == "zap-baseline" for f in findings)
    assert all(f.language == "python" for f in findings)
    assert findings[0].cwe == "CWE-1021"
    assert findings[0].extra["plugin_id"] == "10020"
    assert findings[0].extra["url"] == "http://example.test/"
