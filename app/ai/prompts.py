from __future__ import annotations

import json
from typing import Any

from app.ai.selector import SelectedFile
from app.models.finding import CodeInventory, Finding

SYSTEM_PROMPT = """You are a senior application security reviewer.
Analyze ONLY the source files provided in the user message.
Report real security issues that are evidenced by the given code.
Do NOT invent files, line numbers, CVEs, or issues outside the provided snippets.
Do NOT repeat issues that are already listed in the existing_sast_findings section unless you have materially stronger evidence.
Return ONLY valid JSON matching this schema:
{
  "findings": [
    {
      "title": "short title",
      "description": "why this is a security issue, with evidence from the code",
      "severity": "critical|high|medium|low|info",
      "cwe": "CWE-xxx or null",
      "file": "relative/path.ext",
      "line": 12,
      "remediation": "concrete fix advice"
    }
  ]
}
If there are no issues, return {"findings": []}.
"""


def _inventory_summary(inventories: list[CodeInventory]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for inv in inventories:
        summary.append(
            {
                "language": inv.language,
                "files_count": inv.files_count,
                "modules_sample": inv.modules[:40],
                "imports_sample": inv.imports[:40],
                "dependency_files": inv.dependency_files,
            }
        )
    return summary


def _sast_summary(findings: list[Finding], limit: int = 40) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings:
        if f.source == "ai":
            continue
        out.append(
            {
                "source": f.source,
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "file": f.file,
                "line": f.line,
                "cwe": f.cwe,
            }
        )
        if len(out) >= limit:
            break
    return out


def build_user_prompt(
    selected: list[SelectedFile],
    findings: list[Finding],
    inventories: list[CodeInventory],
    max_findings: int,
) -> str:
    payload = {
        "instructions": (
            f"Return at most {max_findings} findings. "
            "Prefer high-impact authenticated/injection/crypto/secrets issues."
        ),
        "inventory_summary": _inventory_summary(inventories),
        "existing_sast_findings": _sast_summary(findings),
        "files": [
            {"path": item.rel_path, "content": item.content} for item in selected
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


REPAIR_PROMPT = (
    "Your previous reply was not valid JSON for the required schema. "
    "Reply again with ONLY a JSON object: {\"findings\": [...]}."
)
