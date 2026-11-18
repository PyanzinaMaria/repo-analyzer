"""Pydantic output schemas for LLM modes (spec §6.3, §6.4)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.sast.cwe_map import norm_cwe


def _clamp01(v) -> float:
    try:
        v = float(v)
    except (TypeError, ValueError):
        return 0.0
    if v > 1.0 and v <= 100.0:  # some models answer in percent
        v = v / 100.0
    return max(0.0, min(1.0, v))


class TriageResult(BaseModel):
    verdict: Literal["true_positive", "false_positive", "uncertain"]
    confidence: float = Field(ge=0.0, le=1.0)
    cwe: str | None = None
    source: str | None = None
    sink: str | None = None
    sanitizers: list[str] = Field(default_factory=list)
    preconditions: str | None = None
    explanation: str

    @field_validator("confidence", mode="before")
    @classmethod
    def _conf(cls, v):
        return _clamp01(v)

    @field_validator("cwe", mode="before")
    @classmethod
    def _cwe(cls, v):
        return norm_cwe(v) if v else None

    @field_validator("verdict", mode="before")
    @classmethod
    def _verdict(cls, v):
        s = str(v).strip().lower().replace(" ", "_").replace("-", "_")
        return {"tp": "true_positive", "fp": "false_positive", "true": "true_positive",
                "false": "false_positive", "vulnerable": "true_positive",
                "not_vulnerable": "false_positive"}.get(s, s)

    @field_validator("sanitizers", mode="before")
    @classmethod
    def _san(cls, v):
        if v is None:
            return []
        return [v] if isinstance(v, str) else v

    @property
    def score(self) -> float:
        """Ranking score (spec §6.3)."""
        if self.verdict == "true_positive":
            return self.confidence
        if self.verdict == "uncertain":
            return 0.5 * self.confidence
        return 0.0


class TriageItem(TriageResult):
    finding: int


class TriageBatchResult(BaseModel):
    """Several findings judged in one call (cuts request count on rate-limited free tiers)."""
    results: list[TriageItem] = Field(default_factory=list)


class DiscoveredVuln(BaseModel):
    file: str
    start_line: int
    end_line: int
    function: str | None = None
    cwe: str
    title: str
    confidence: float = Field(ge=0.0, le=1.0)
    source_to_sink: list[str] = Field(default_factory=list)
    explanation: str
    exploit_sketch: str | None = None

    @field_validator("confidence", mode="before")
    @classmethod
    def _conf(cls, v):
        return _clamp01(v)

    @field_validator("cwe", mode="before")
    @classmethod
    def _cwe(cls, v):
        return norm_cwe(v) or "CWE-unknown"

    @field_validator("source_to_sink", mode="before")
    @classmethod
    def _chain(cls, v):
        if v is None:
            return []
        return [v] if isinstance(v, str) else [str(x) for x in v]

    @field_validator("end_line", mode="after")
    @classmethod
    def _end(cls, v, info):
        start = info.data.get("start_line")
        return max(v, start) if isinstance(start, int) else v


class DiscoveryResult(BaseModel):
    vulnerabilities: list[DiscoveredVuln] = Field(default_factory=list)


SCHEMA_HINTS = {
    "TriageResult": """{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "confidence": number between 0 and 1,
  "cwe": "CWE-<id>" or null,
  "source": "where untrusted data comes from" or null,
  "sink": "the dangerous operation" or null,
  "sanitizers": ["validation/sanitization on the path", ...],
  "preconditions": "what an attacker needs" or null,
  "explanation": "2-5 sentences for an audit report"
}""",
    "TriageBatchResult": """{
  "results": [
    {
      "finding": <finding number>,
      "verdict": "true_positive" | "false_positive" | "uncertain",
      "confidence": number between 0 and 1,
      "cwe": "CWE-<id>" or null,
      "source": "where untrusted data comes from" or null,
      "sink": "the dangerous operation" or null,
      "sanitizers": ["validation/sanitization on the path", ...],
      "preconditions": "what an attacker needs" or null,
      "explanation": "2-5 sentences for an audit report"
    }
  ]
}""",
    "DiscoveryResult": """{
  "vulnerabilities": [
    {
      "file": "repo-relative path exactly as shown",
      "start_line": int, "end_line": int,
      "function": "function name" or null,
      "cwe": "CWE-<id>",
      "title": "short title",
      "confidence": number between 0 and 1,
      "source_to_sink": ["step 1", "step 2", ...],
      "explanation": "2-5 sentences",
      "exploit_sketch": "high-level idea, no working payloads" or null
    }
  ]
}""",
}
