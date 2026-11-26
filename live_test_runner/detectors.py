"""Quality-problem detectors over live HTTP observations with deduplication."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


SECURITY_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
)

# Kinds that enter problems_total / problems_unique (proofs are coverage only).
PROBLEM_KINDS = frozenset({
    "http_4xx",
    "http_5xx",
    "missing_security_headers",
    "insecure_cookies",
    "reflected_input",
})


def normalize_page(page_path: str, url: str = "") -> str:
    """Stable page key without host or query noise."""
    if page_path:
        path = page_path.split("?", 1)[0]
        return path if path.startswith("/") else f"/{path}"
    if url:
        return urlparse(url).path or "/"
    return "/"


def fingerprint(kind: str, detail: str) -> str:
    """Level-2 unique key: kind + detail (page is attached separately)."""
    return f"{kind}|{detail}"


@dataclass
class Finding:
    kind: str
    detail: str
    pages: set[str] = field(default_factory=set)
    occurrences: int = 0
    example_urls: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.kind, self.detail)

    def observe(self, page: str, url: str = "") -> None:
        self.occurrences += 1
        if page:
            self.pages.add(page)
        if url and url not in self.example_urls and len(self.example_urls) < 3:
            self.example_urls.append(url)

    def as_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "kind": self.kind,
            "detail": self.detail,
            "pages": sorted(self.pages),
            "occurrences": self.occurrences,
            "example_urls": list(self.example_urls),
        }


@dataclass
class ProblemReport:
    http_4xx: int = 0
    http_5xx: int = 0
    missing_security_headers: int = 0
    insecure_cookies: int = 0
    reflected_input: int = 0
    proof_reached: int = 0
    findings: dict[str, Finding] = field(default_factory=dict)

    @property
    def problems_total(self) -> int:
        """Raw detector hits (not deduplicated)."""
        return (
            self.http_4xx
            + self.http_5xx
            + self.missing_security_headers
            + self.insecure_cookies
            + self.reflected_input
        )

    @property
    def problems_unique(self) -> int:
        """Unique findings by kind|detail across all pages."""
        return sum(1 for key in self.findings if key.split("|", 1)[0] in PROBLEM_KINDS)

    def record(
        self,
        kind: str,
        detail: str,
        *,
        page: str,
        url: str = "",
        count: int = 1,
    ) -> None:
        key = fingerprint(kind, detail)
        finding = self.findings.get(key)
        if finding is None:
            finding = Finding(kind=kind, detail=detail)
            self.findings[key] = finding
        for _ in range(count):
            finding.observe(page, url)

    def as_dict(self) -> dict[str, Any]:
        findings = [
            item.as_dict()
            for item in sorted(
                self.findings.values(),
                key=lambda f: (-f.occurrences, f.fingerprint),
            )
        ]
        return {
            "http_4xx": self.http_4xx,
            "http_5xx": self.http_5xx,
            "missing_security_headers": self.missing_security_headers,
            "insecure_cookies": self.insecure_cookies,
            "reflected_input": self.reflected_input,
            "proof_reached": self.proof_reached,
            "problems_total": self.problems_total,
            "problems_unique": self.problems_unique,
            "findings": findings,
        }


def merge_findings(finding_lists: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Merge finding dicts from several runs into a global unique list."""
    merged: dict[str, Finding] = {}
    for group in finding_lists:
        for raw in group:
            key = raw.get("fingerprint") or fingerprint(raw["kind"], raw["detail"])
            finding = merged.get(key)
            if finding is None:
                finding = Finding(kind=raw["kind"], detail=raw["detail"])
                merged[key] = finding
            finding.occurrences += int(raw.get("occurrences", 0))
            finding.pages.update(raw.get("pages") or [])
            for url in raw.get("example_urls") or []:
                if url not in finding.example_urls and len(finding.example_urls) < 3:
                    finding.example_urls.append(url)
    return [
        item.as_dict()
        for item in sorted(merged.values(), key=lambda f: (-f.occurrences, f.fingerprint))
    ]


def unique_problem_count(findings: list[dict[str, Any]]) -> int:
    return sum(1 for item in findings if item.get("kind") in PROBLEM_KINDS)


def _header_map(headers) -> dict[str, str]:
    if hasattr(headers, "items"):
        return {str(k).lower(): str(v) for k, v in headers.items()}
    return {}


def inspect_response(
    report: ProblemReport,
    *,
    status_code: int,
    headers,
    body: str,
    url: str,
    submitted_values: tuple[str, ...] = (),
    page_path: str = "",
) -> None:
    """Accumulate raw hits and deduplicated findings for one HTTP response."""
    hdrs = _header_map(headers)
    page = normalize_page(page_path, url)

    if 400 <= status_code < 500:
        report.http_4xx += 1
        report.record("http_4xx", str(status_code), page=page, url=url)
    elif status_code >= 500:
        report.http_5xx += 1
        report.record("http_5xx", str(status_code), page=page, url=url)

    missing = [name for name in SECURITY_HEADERS if name not in hdrs]
    if missing:
        report.missing_security_headers += len(missing)
        for name in missing:
            report.record("missing_security_headers", name, page=page, url=url)

    raw_cookies: list[str] = []
    if hasattr(headers, "get_list"):
        raw_cookies = list(headers.get_list("set-cookie"))
    elif "set-cookie" in hdrs:
        raw_cookies = [hdrs["set-cookie"]]
    for cookie in raw_cookies:
        lower = cookie.lower()
        issues = []
        if "httponly" not in lower:
            issues.append("missing_httponly")
        if "secure" not in lower:
            issues.append("missing_secure")
        if "samesite" not in lower:
            issues.append("missing_samesite")
        if issues:
            report.insecure_cookies += len(issues)
            for issue in issues:
                report.record("insecure_cookies", issue, page=page, url=url)

    for value in submitted_values:
        if value and value in body and value not in ("on", "off", "plain", "empty"):
            report.reflected_input += 1
            report.record("reflected_input", value, page=page, url=url)
            break

    slug = page.lstrip("/")
    if slug.endswith("-proof") or "proof" in slug:
        report.proof_reached += 1
        report.record("proof_reached", slug or page, page=page, url=url)
