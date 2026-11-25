from __future__ import annotations

import re
from typing import Iterable

from app.models.finding import Finding, Severity as FindingSeverity
from app.security.models import Severity, Source, VulnClass, VulnHypothesis

_CWE_TO_CLASS = {
    "CWE-089": VulnClass.sqli, "CWE-89": VulnClass.sqli,
    "CWE-079": VulnClass.xss, "CWE-79": VulnClass.xss,
    "CWE-022": VulnClass.path_traversal, "CWE-22": VulnClass.path_traversal,
    "CWE-601": VulnClass.open_redirect,
    "CWE-078": VulnClass.cmd_injection, "CWE-78": VulnClass.cmd_injection,
    "CWE-611": VulnClass.xxe,
    "CWE-918": VulnClass.ssrf,
    "CWE-502": VulnClass.insecure_deserialization,
    "CWE-798": VulnClass.hardcoded_secret,
    "CWE-693": VulnClass.missing_headers,
    "CWE-209": VulnClass.error_disclosure,
    "CWE-1427": VulnClass.prompt_injection,
}

_RULE_PATTERNS: tuple[tuple[str, VulnClass], ...] = (
    (r"sql", VulnClass.sqli),
    (r"xss|cross[-_ ]site", VulnClass.xss),
    (r"path[-_ ]?(traversal|injection)|directory[-_ ]traversal|zip[-_ ]?slip", VulnClass.path_traversal),
    (r"redirect|open[-_ ]redirect", VulnClass.open_redirect),
    (r"command|shell|exec|subprocess", VulnClass.cmd_injection),
    (r"xxe|xml[-_ ]external", VulnClass.xxe),
    (r"ssrf|server[-_ ]side[-_ ]request", VulnClass.ssrf),
    (r"deserial|pickle|unpickle|yaml\.load", VulnClass.insecure_deserialization),
    (r"secret|hardcoded|password|credential|api[_-]?key", VulnClass.hardcoded_secret),
    (r"header|csp|hsts|frame[-_ ]options", VulnClass.missing_headers),
    (r"traceback|stack[-_ ]?trace|error[-_ ]?disclosure|debug", VulnClass.error_disclosure),
    (r"prompt[-_ ]?inject|llm", VulnClass.prompt_injection),
)

_SEVERITY_MAP = {
    FindingSeverity.critical: Severity.critical,
    FindingSeverity.high: Severity.high,
    FindingSeverity.medium: Severity.medium,
    FindingSeverity.low: Severity.low,
    FindingSeverity.info: Severity.info,
    FindingSeverity.unknown: Severity.medium,
}

# SAST confidence per source: dedicated engines are more trustworthy than a
# generic grep-like match.
_SOURCE_CONFIDENCE = {
    "codeql": 0.85,
    "semgrep": 0.75,
    "bandit": 0.7,
    "eslint": 0.6,
    "pip-audit": 0.4,
    "ai": 0.55,
    "iris": 0.8,
    "pentest": 0.9,
}


def cwe_to_vuln_class(cwe: str | None) -> VulnClass | None:
    """Map a CWE id (any case, with/without zero padding) to a pipeline class."""
    if not cwe:
        return None
    key = cwe.upper().strip()
    if key in _CWE_TO_CLASS:
        return _CWE_TO_CLASS[key]
    m = re.match(r"CWE-0*(\d+)", key)
    if m:
        return _CWE_TO_CLASS.get(f"CWE-{m.group(1).zfill(3)}")
    return None


def classify_finding(finding: Finding) -> VulnClass | None:
    cwe = (finding.cwe or "").upper().strip()
    if cwe in _CWE_TO_CLASS:
        return _CWE_TO_CLASS[cwe]
    haystack = " ".join(filter(None, [finding.rule_id, finding.title])).lower()
    for pattern, vuln_class in _RULE_PATTERNS:
        if re.search(pattern, haystack):
            return vuln_class
    return None


def _endpoint_from_finding(finding: Finding) -> tuple[str | None, str | None]:
    """Best-effort endpoint/param extraction from a finding's metadata."""
    extra = finding.extra or {}
    url = extra.get("url") or extra.get("endpoint") or extra.get("route")
    param = extra.get("param") or extra.get("parameter")
    if not url:
        text = f"{finding.title} {finding.description}"
        m = re.search(r"(/[\w\-./{}]+)", text)
        if m:
            url = m.group(1)
    return (str(url) if url else None, str(param) if param else None)


def findings_to_hypotheses(findings: Iterable[Finding], *, min_confidence: float = 0.0) -> list[VulnHypothesis]:
    """Convert SAST/AI/DAST findings into verification hypotheses (deduplicated)."""
    hypotheses: list[VulnHypothesis] = []
    seen: set[tuple[str, str | None, int | None]] = set()
    for finding in findings:
        vuln_class = classify_finding(finding)
        if vuln_class is None:
            continue
        if vuln_class in {VulnClass.missing_headers, VulnClass.error_disclosure}:
            # target-level checks are produced by the verifier itself
            continue
        confidence = _SOURCE_CONFIDENCE.get((finding.source or "").lower(), 0.5)
        if confidence < min_confidence:
            continue
        key = (vuln_class.value, finding.file, finding.line)
        if key in seen:
            continue
        seen.add(key)
        endpoint, param = _endpoint_from_finding(finding)
        hypotheses.append(VulnHypothesis(
            vuln_class=vuln_class,
            source=Source.sast,
            title=finding.title,
            description=finding.description,
            cwe=finding.cwe or vuln_class.default_cwe,
            confidence=confidence,
            severity=_SEVERITY_MAP.get(finding.severity, Severity.medium),
            file=finding.file,
            line=finding.line,
            endpoint=endpoint,
            param=param,
            evidence=f"правило {finding.rule_id or '—'} ({finding.source})",
            meta={"finding_id": finding.id, "rule_id": finding.rule_id,
                  "source": finding.source, "remediation": finding.remediation},
        ))
    return hypotheses
