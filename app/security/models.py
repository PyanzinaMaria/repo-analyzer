from __future__ import annotations

"""Unified security model: hypotheses, probe plans, verifications.

A *hypothesis* is a claim "this place in the code may be vulnerable to X"
produced by any source (SAST, LLM code review, RL agent, manual triage).
A *probe plan* is one concrete attempt to confirm it against a running target.
A *verification* is the verdict after executing the plan (with evidence).

The same hypothesis can carry no URL (then the verifier falls back to crawling)
or a precise endpoint+parameter (then the verifier targets it directly).
"""

import hashlib
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class VulnClass(str, Enum):
    """Vulnerability classes the pipeline understands.

    Covers classical application security (not only LLM-specific ones) plus a
    few LLM-application classes that are reachable over plain HTTP.
    """

    sqli = "sqli"
    xss = "xss"
    path_traversal = "path_traversal"
    open_redirect = "open_redirect"
    cmd_injection = "cmd_injection"
    xxe = "xxe"
    ssrf = "ssrf"
    insecure_deserialization = "insecure_deserialization"
    hardcoded_secret = "hardcoded_secret"
    missing_headers = "missing_headers"
    error_disclosure = "error_disclosure"
    prompt_injection = "prompt_injection"

    @property
    def default_cwe(self) -> str:
        return _CWE.get(self, "CWE-693")


_CWE = {
    VulnClass.sqli: "CWE-089",
    VulnClass.xss: "CWE-079",
    VulnClass.path_traversal: "CWE-022",
    VulnClass.open_redirect: "CWE-601",
    VulnClass.cmd_injection: "CWE-078",
    VulnClass.xxe: "CWE-611",
    VulnClass.ssrf: "CWE-918",
    VulnClass.insecure_deserialization: "CWE-502",
    VulnClass.hardcoded_secret: "CWE-798",
    VulnClass.missing_headers: "CWE-693",
    VulnClass.error_disclosure: "CWE-209",
    VulnClass.prompt_injection: "CWE-1427",
}


class Source(str, Enum):
    sast = "sast"
    llm_review = "llm_review"
    rl = "rl"
    crawl = "crawl"
    manual = "manual"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class VulnHypothesis(BaseModel):
    """A candidate vulnerability to be confirmed (or refuted) dynamically."""

    id: str = ""
    vuln_class: VulnClass
    source: Source
    title: str
    description: str = ""
    cwe: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    severity: Severity = Severity.medium
    file: str | None = None
    line: int | None = None
    function: str | None = None
    endpoint: str | None = None      # absolute URL or path ("/search")
    method: str | None = None        # GET / POST
    param: str | None = None         # parameter to inject into
    evidence: str = ""               # why the source believes it (code snippet, rule)
    meta: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:  # noqa: D401
        if not self.id:
            raw = f"{self.source}:{self.vuln_class}:{self.file}:{self.line}:{self.endpoint}:{self.param}"
            self.id = "hyp-" + hashlib.sha1(raw.encode()).hexdigest()[:10]
        if not self.cwe:
            self.cwe = self.vuln_class.default_cwe

    def key(self) -> tuple[str, str | None, str | None]:
        """Deduplication key: concrete endpoint+param when known, else file:line."""
        if self.endpoint:
            return (self.vuln_class.value,
                    f"{self.endpoint}|{(self.method or 'GET').upper()}",
                    self.param)
        return (self.vuln_class.value, f"{self.file}:{self.line}", self.param)


class ProbePlan(BaseModel):
    """One concrete request set prepared for a hypothesis."""

    id: str = ""
    hypothesis_id: str
    plugin: str
    strategy: str
    url: str
    method: str = "GET"
    param: str
    payload: str
    cwe: str | None = None
    severity: Severity = Severity.medium
    meta: dict[str, Any] = Field(default_factory=dict)


class Detection(BaseModel):
    """What a plugin detector found in a response."""

    matched: bool
    kind: str                       # e.g. "sql_error", "reflection", "passwd_marker"
    evidence: str = ""
    confidence: float = 0.5
    request: str = ""
    response_snippet: str = ""


class Verdict(str, Enum):
    confirmed = "confirmed"
    refuted = "refuted"
    uncertain = "uncertain"
    skipped = "skipped"


class Verification(BaseModel):
    hypothesis_id: str
    verdict: Verdict
    confidence: float = 0.0
    severity: Severity = Severity.medium
    explanation: str = ""
    evidence: str = ""
    plugin: str | None = None
    strategy: str | None = None
    url: str | None = None
    payload: str | None = None
    request: str | None = None
    response: str | None = None
    judged_by: str = "rules"       # rules | llm | rules+llm
    meta: dict[str, Any] = Field(default_factory=dict)


class ReviewResult(BaseModel):
    hypotheses: list[VulnHypothesis] = Field(default_factory=list)
    findings: list[Any] = Field(default_factory=list)  # app.models.finding.Finding
    meta: dict[str, Any] = Field(default_factory=dict)


class SecurityRun(BaseModel):
    repo: str
    target_url: str | None = None
    hypotheses: list[VulnHypothesis] = Field(default_factory=list)
    verifications: list[Verification] = Field(default_factory=list)
    findings: list[Any] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)
