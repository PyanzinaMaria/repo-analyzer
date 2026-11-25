"""Typed loaders for the LLM-flow catalog (config/llmflow/*.yaml): SDKs, sinks, sources, gates, KB."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.yaml_configs import CONFIG_DIR

LLMFLOW_DIR = CONFIG_DIR / "llmflow"

Channel = Literal["chat", "completion", "responses", "tool_call"]
GateKind = Literal["deterministic", "confirmation", "weak"]


class SdkCall(BaseModel):
    id: str
    callee: str                         # Semgrep expression without arguments, e.g. "$C.chat.completions.create"
    channel: Channel = "chat"
    model_arg: str | None = "model"
    model_pos: int | None = None
    prompt_args: list[str] = Field(default_factory=list)
    prompt_pos: list[int] = Field(default_factory=list)
    tools_arg: str | None = None
    inside_import: list[str] = Field(default_factory=list)   # file must import one of these modules
    require_kwargs: list[str] = Field(default_factory=list)  # call must pass these keyword arguments
    exclude: list[str] = Field(default_factory=list)         # callees this entry must not match
    receiver_regex: str | None = None   # alternative to inside_import: receiver ($C) text matches this regex


class Sdk(BaseModel):
    sdk: str
    provider: str
    imports: list[str] = Field(default_factory=list)
    calls: list[SdkCall]


class Pattern(BaseModel):
    """A Semgrep pattern plus optional metavariable-regex constraints and exclusions."""
    model_config = ConfigDict(populate_by_name=True)

    pattern: str
    regex: dict[str, str] = Field(default_factory=dict)
    not_: list[str] = Field(default_factory=list, alias="not")


class SinkClass(BaseModel):
    S: float
    cwe: str
    title: str
    enabled: bool = True
    patterns: list[Pattern]

    @field_validator("patterns")
    @classmethod
    def _binds_x(cls, v: list[Pattern]) -> list[Pattern]:
        for p in v:
            if "$X" not in p.pattern:
                raise ValueError(f"sink pattern must bind $X: {p.pattern}")
        return v


class SinksConfig(BaseModel):
    classes: dict[str, SinkClass]

    def enabled(self, extra: set[str] | None = None) -> dict[str, SinkClass]:
        extra = extra or set()
        return {k: v for k, v in self.classes.items() if v.enabled or k in extra}


class SourceKind(BaseModel):
    E: float
    title: str
    patterns: list[Pattern]


class SourceDefaults(BaseModel):
    unknown: float = 0.5
    route_param: float = 1.0
    route_param_auth: float = 0.3
    auth_markers: str = r"(?i)(login_required|auth|admin|permission)"


class SourcesConfig(BaseModel):
    kinds: dict[str, SourceKind]
    defaults: SourceDefaults = Field(default_factory=SourceDefaults)


class Gate(BaseModel):
    id: str
    kind: GateKind
    title: str
    applies_to: list[str] = Field(default_factory=lambda: ["*"])
    patterns: list[str]
    regex: dict[str, str] = Field(default_factory=dict)

    def applies(self, sink_class: str) -> bool:
        return "*" in self.applies_to or sink_class in self.applies_to


class GatesConfig(BaseModel):
    factors: dict[GateKind, float]
    gates: list[Gate]


class ModelR(BaseModel):
    default: float = 0.5
    channels: dict[str, float] = Field(default_factory=dict)


class KbModel(BaseModel):
    id: str
    provider: str
    aliases: list[str]
    status: str = "active"
    features: dict[str, bool] = Field(default_factory=dict)
    R: ModelR = Field(default_factory=ModelR)


class KbDefaults(BaseModel):
    R: float = 0.5
    min: float = 0.3
    max: float = 0.9


class KbConfig(BaseModel):
    defaults: KbDefaults = Field(default_factory=KbDefaults)
    models: list[KbModel]


class Catalog(BaseModel):
    sdks: list[Sdk]
    sinks: SinksConfig
    sources: SourcesConfig
    gates: GatesConfig
    kb: KbConfig
    hygiene_path: Path

    def sdk_calls(self) -> list[tuple[Sdk, SdkCall]]:
        return [(s, c) for s in self.sdks for c in s.calls]

    def call(self, call_id: str) -> tuple[Sdk, SdkCall]:
        for s, c in self.sdk_calls():
            if c.id == call_id:
                return s, c
        raise KeyError(call_id)


def _read(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load_catalog(root: Path | str = LLMFLOW_DIR) -> Catalog:
    root = Path(root)
    sdks = [Sdk.model_validate(_read(p)) for p in sorted((root / "sdks").glob("*.yaml"))]
    ids = [c.id for s in sdks for c in s.calls]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise ValueError(f"duplicate SDK call ids: {sorted(dup)}")
    return Catalog(
        sdks=sdks,
        sinks=SinksConfig.model_validate(_read(root / "sinks.yaml")),
        sources=SourcesConfig.model_validate(_read(root / "sources.yaml")),
        gates=GatesConfig.model_validate(_read(root / "gates.yaml")),
        kb=KbConfig.model_validate(_read(root / "kb.yaml")),
        hygiene_path=root / "hygiene.yaml",
    )


@lru_cache(maxsize=1)
def default_catalog() -> Catalog:
    return load_catalog()
