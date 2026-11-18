from __future__ import annotations

from pathlib import Path

from jinja2 import BaseLoader, Environment

from app.models.report import ScanResult

_DAST_MD = """# DAST report

- Scan: `{{ result.scan_id }}`
- Target: `{{ result.meta.dast.target_url if result.meta.dast else "" }}`
- Status: `{{ result.meta.dast.status if result.meta.dast else "" }}`
- Findings: {{ result.summary.total_findings }}

## By severity

{% for sev, count in (result.summary.by_severity or {}).items() -%}
- {{ sev }}: {{ count }}
{% endfor %}

## Findings

{% for f in result.findings -%}
### {{ f.title }} ({{ f.severity.value }})

- source: `{{ f.source }}`
- language: `{{ f.language }}`
- cwe: {{ f.cwe or "—" }}
- url: {{ (f.extra or {}).get("url") or "—" }}
- evidence: {{ (f.extra or {}).get("evidence") or "—" }}

{{ f.description }}

{% endfor %}
"""


def write_dast_json(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


def render_dast_markdown(result: ScanResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    env = Environment(loader=BaseLoader(), autoescape=False)
    template = env.from_string(_DAST_MD)
    path.write_text(template.render(result=result), encoding="utf-8")
    return path


def write_dast_bundle(result: ScanResult, reports_dir: Path) -> dict[str, str]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = write_dast_json(result, reports_dir / "dast_report.json")
    md_path = render_dast_markdown(result, reports_dir / "dast_report.md")
    return {"json": str(json_path), "markdown": str(md_path)}
