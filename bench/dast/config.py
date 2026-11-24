"""config/dast.yaml loader plus the DAST finding/result models shared by adapters, eval and compare."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

from app.core.yaml_configs import CONFIG_DIR, REPO_ROOT

DAST_KINDS = ("owasp-java", "owasp-python", "realvuln")


class ZapTool(BaseModel):
    image: str = "ghcr.io/zaproxy/zaproxy:stable"
    time_limit_m: int = 30


class WapitiTool(BaseModel):
    executable: str = "wapiti"
    modules: str = "common"
    level: int = 2


class NucleiTool(BaseModel):
    executable: str = "nuclei"
    templates_dir: str | None = None
    severity: str = "low,medium,high,critical"


class OffatTool(BaseModel):
    executable: str = "offat"


class NiktoTool(BaseModel):
    image: str = "sullo/nikto:latest"


class TargetSpec(BaseModel):
    scheme: str = "http"
    port: int
    container: str
    image: str


class DastBenchConfig(BaseModel):
    scan_timeout_s: int = 1800
    boot_timeout_s: int = 600
    network: str = "repo-analyzer-dast"
    owasp_java: TargetSpec = TargetSpec(scheme="https", port=8443, container="dast-bench-owasp-java-app",
                                        image="dast-bench:owasp-java")
    owasp_python: TargetSpec = TargetSpec(scheme="http", port=5000, container="dast-bench-owasp-python-app",
                                          image="dast-bench:owasp-python")
    tools: dict[str, BaseModel] = Field(default_factory=dict)

    def tool(self, name: str) -> BaseModel:
        if name not in self.tools:
            raise KeyError(f"unknown DAST tool {name!r} (config/dast.yaml tools: {', '.join(self.tools)})")
        return self.tools[name]


_SPEC_BY_TOOL: dict[str, type[BaseModel]] = {
    "zap": ZapTool, "wapiti": WapitiTool, "nuclei": NucleiTool, "offat": OffatTool, "nikto": NiktoTool,
}
_SPEC_BY_KIND = {"owasp-java": "owasp_java", "owasp-python": "owasp_python"}


def load_dast_config(path: Path | str = CONFIG_DIR / "dast.yaml") -> DastBenchConfig:
    """Manual load: `tools:` values have per-tool models, so a single pydantic validate can't express them."""
    p = Path(path)
    if not p.is_absolute() and not p.exists():
        p = REPO_ROOT / p
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    tools_raw = raw.pop("tools") or {}
    tools = {}
    for name, spec in tools_raw.items():
        cls = _SPEC_BY_TOOL.get(name)
        if cls is None:
            raise KeyError(f"unknown DAST tool {name!r} in {p}")
        tools[name] = cls(**{k: v for k, v in (spec or {}).items() if v is not None})
    cfg = DastBenchConfig(**raw)
    cfg.tools = tools
    return cfg


def target_spec(cfg: DastBenchConfig, kind: Literal["owasp-java", "owasp-python"]) -> TargetSpec:
    return getattr(cfg, _SPEC_BY_KIND[kind])


# --------------------------------------------------------------------------- models


class DastFinding(BaseModel):
    """One scanner result, normalized across tools. Matching/metrics read url + cwe only."""

    tool: str
    rule_id: str
    title: str
    severity: str = "unknown"
    cwe: list[str] = Field(default_factory=list)
    url: str = ""
    method: str = ""
    parameter: str | None = None
    evidence: str | None = None
    message: str = ""


class TargetInfo(BaseModel):
    """A live target the adapters scan. host_url for native tools, scan_url for dockerized tools."""

    target_id: str
    kind: str
    host_url: str                    # http://127.0.0.1:5000
    scan_url: str                    # container-DNS URL for dockerized tools
    network: str = "repo-analyzer-dast"
    spec_path: str | None = None     # generated/live OpenAPI spec for OFFAT


class DastToolResult(BaseModel):
    tool: str
    target_id: str
    ok: bool = False
    skipped: bool = False
    cached: bool = False
    reason: str = ""
    seconds: float = 0.0
    findings: int = 0
    cmd: list[str] = Field(default_factory=list)
    error: str = ""
    meta: dict = Field(default_factory=dict)
