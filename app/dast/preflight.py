from __future__ import annotations

import logging
import uuid
from typing import Any
from urllib.parse import urlparse

import httpx

from app.dast.fingerprint import build_fingerprint
from app.models.finding import Finding, Severity

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", Severity.medium, "CWE-693"),
    "x-frame-options": ("X-Frame-Options", Severity.medium, "CWE-1021"),
    "x-content-type-options": ("X-Content-Type-Options", Severity.low, "CWE-693"),
    "referrer-policy": ("Referrer-Policy", Severity.low, "CWE-200"),
    "strict-transport-security": ("Strict-Transport-Security", Severity.medium, "CWE-319"),
}


def _finding(
    *,
    title: str,
    description: str,
    severity: Severity,
    cwe: str | None,
    url: str,
    evidence: str,
    language: str,
    rule_id: str,
) -> Finding:
    return Finding(
        id=f"dast-preflight-{rule_id}-{uuid.uuid4().hex[:8]}",
        title=title,
        description=description,
        severity=severity,
        cwe=cwe,
        rule_id=rule_id,
        source="dast-preflight",
        language=language,
        remediation=None,
        extra={"url": url, "method": "GET", "evidence": evidence},
    )


def run_preflight(
    target_url: str,
    *,
    follow_redirects: bool = True,
    timeout_seconds: float = 15.0,
    language: str = "http",
) -> tuple[list[Finding], dict[str, Any]]:
    """Probe the target once and emit baseline HTTP security findings."""
    findings: list[Finding] = []
    meta: dict[str, Any] = {"ok": False}

    try:
        with httpx.Client(
            follow_redirects=follow_redirects,
            timeout=timeout_seconds,
            verify=True,
        ) as client:
            response = client.get(target_url)
    except httpx.HTTPError as exc:
        logger.warning("DAST preflight request failed for %s: %s", target_url, exc)
        meta["error"] = str(exc)
        return findings, meta

    headers = {k: v for k, v in response.headers.items()}
    body_sample = response.text[:4000] if response.text else ""
    final_url = str(response.url)
    fingerprint = build_fingerprint(
        url=target_url,
        status_code=response.status_code,
        headers=headers,
        body_sample=body_sample,
        final_url=final_url,
    )
    meta.update({"ok": True, "status_code": response.status_code, "fingerprint": fingerprint})

    parsed = urlparse(final_url)
    if parsed.scheme == "http":
        findings.append(
            _finding(
                title="Target served over cleartext HTTP",
                description="The application endpoint is reachable without TLS.",
                severity=Severity.medium,
                cwe="CWE-319",
                url=final_url,
                evidence=f"scheme={parsed.scheme}",
                language=language,
                rule_id="cleartext-http",
            )
        )
    elif parsed.scheme == "https" and "strict-transport-security" not in fingerprint["headers"]:
        findings.append(
            _finding(
                title="Missing Strict-Transport-Security header",
                description="HTTPS response does not advertise HSTS.",
                severity=Severity.medium,
                cwe="CWE-319",
                url=final_url,
                evidence="Strict-Transport-Security header not set",
                language=language,
                rule_id="missing-hsts",
            )
        )

    for key, (name, severity, cwe) in SECURITY_HEADERS.items():
        if key == "strict-transport-security":
            continue
        if key not in fingerprint["headers"]:
            findings.append(
                _finding(
                    title=f"Missing {name} header",
                    description=f"Response does not include the {name} security header.",
                    severity=severity,
                    cwe=cwe,
                    url=final_url,
                    evidence=f"{name} header not set",
                    language=language,
                    rule_id=f"missing-{key}",
                )
            )

    server = fingerprint.get("server") or ""
    powered = fingerprint.get("powered_by") or ""
    if server or powered:
        evidence = "; ".join(
            part
            for part in (f"Server={server}" if server else "", f"X-Powered-By={powered}" if powered else "")
            if part
        )
        findings.append(
            _finding(
                title="Server technology disclosure",
                description="Response headers reveal server / framework technology.",
                severity=Severity.info,
                cwe="CWE-200",
                url=final_url,
                evidence=evidence,
                language=language,
                rule_id="tech-disclosure",
            )
        )

    acao = fingerprint["headers"].get("access-control-allow-origin", "")
    acac = fingerprint["headers"].get("access-control-allow-credentials", "").lower()
    if acao == "*":
        sev = Severity.high if acac == "true" else Severity.medium
        findings.append(
            _finding(
                title="Permissive CORS policy",
                description="Access-Control-Allow-Origin is set to wildcard.",
                severity=sev,
                cwe="CWE-942",
                url=final_url,
                evidence=f"ACAO=* ACACredentials={acac or 'unset'}",
                language=language,
                rule_id="cors-wildcard",
            )
        )

    # Set-Cookie flags
    raw_cookies = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
    if not raw_cookies:
        # httpx Headers may expose multiple via get_list; fallback single
        single = response.headers.get("set-cookie")
        raw_cookies = [single] if single else []
    for cookie in raw_cookies:
        lower = cookie.lower()
        issues: list[str] = []
        if "secure" not in lower and parsed.scheme == "https":
            issues.append("missing Secure")
        if "httponly" not in lower:
            issues.append("missing HttpOnly")
        if "samesite" not in lower:
            issues.append("missing SameSite")
        if issues:
            findings.append(
                _finding(
                    title="Weak cookie flags",
                    description="Set-Cookie is missing recommended security attributes.",
                    severity=Severity.medium,
                    cwe="CWE-614",
                    url=final_url,
                    evidence=f"{cookie[:180]} ({', '.join(issues)})",
                    language=language,
                    rule_id="cookie-flags",
                )
            )

    return findings, meta
