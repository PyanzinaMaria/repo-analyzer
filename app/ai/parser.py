from __future__ import annotations

import json
import re
import uuid
from typing import Any

from app.ai.selector import language_for_path
from app.models.finding import Finding, Severity

_SEVERITY_MAP = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
    "informational": Severity.info,
    "unknown": Severity.unknown,
}


def _extract_json_object(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


def _normalize_severity(value: Any) -> Severity:
    if value is None:
        return Severity.unknown
    key = str(value).strip().lower()
    return _SEVERITY_MAP.get(key, Severity.unknown)


def _allowed_files(selected_paths: set[str]) -> set[str]:
    return {p.replace("\\", "/") for p in selected_paths}


def _is_duplicate(candidate: Finding, existing: list[Finding]) -> Finding | None:
    for f in existing:
        if f.source == "ai":
            continue
        if not candidate.file or not f.file:
            continue
        same_file = candidate.file.replace("\\", "/") == f.file.replace("\\", "/")
        if not same_file:
            continue
        same_line = (
            candidate.line is not None
            and f.line is not None
            and candidate.line == f.line
        )
        same_cwe = bool(candidate.cwe and f.cwe and candidate.cwe == f.cwe)
        title_overlap = (
            candidate.title.lower() in f.title.lower()
            or f.title.lower() in candidate.title.lower()
        )
        if same_line or same_cwe or title_overlap:
            return f
    return None


def parse_ai_findings(
    raw_text: str,
    *,
    selected_paths: set[str],
    existing_findings: list[Finding],
    max_findings: int,
) -> list[Finding]:
    data = _extract_json_object(raw_text)
    items: list[Any]
    if isinstance(data, dict):
        items = data.get("findings") or data.get("issues") or []
    elif isinstance(data, list):
        items = data
    else:
        raise ValueError("AI JSON root must be object or array")

    if not isinstance(items, list):
        raise ValueError("AI findings must be a list")

    allowed = _allowed_files(selected_paths)
    out: list[Finding] = []
    for idx, item in enumerate(items):
        if len(out) >= max_findings:
            break
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        description = str(item.get("description") or "").strip()
        file_path = item.get("file")
        if not title or not description or not file_path:
            continue
        rel = str(file_path).replace("\\", "/").lstrip("./")
        if rel not in allowed:
            # Reject hallucinations outside selected context
            continue

        line_raw = item.get("line")
        line: int | None
        try:
            line = int(line_raw) if line_raw is not None else None
        except (TypeError, ValueError):
            line = None
        if line is not None and line <= 0:
            line = None

        cwe = item.get("cwe")
        cwe_str = str(cwe).strip() if cwe else None
        if cwe_str and cwe_str.lower() in {"null", "none", "-"}:
            cwe_str = None

        remediation = item.get("remediation")
        remediation_str = str(remediation).strip() if remediation else None

        finding = Finding(
            id=f"ai-{uuid.uuid4().hex[:12]}",
            title=title[:200],
            description=description,
            severity=_normalize_severity(item.get("severity")),
            cwe=cwe_str,
            file=rel,
            line=line,
            rule_id=f"AI-{idx + 1:03d}",
            source="ai",
            language=language_for_path(rel),
            remediation=remediation_str,
            extra={},
        )
        dup = _is_duplicate(finding, existing_findings)
        if dup is not None:
            finding.extra["duplicate_of"] = dup.id
            # Drop near-duplicates from deterministic scanners
            continue
        out.append(finding)
    return out
