"""Benchmark/evaluation configs (config/benchmark.yaml, config/eval.yaml) and the research data directory.

Toolchain configs (SAST, sinks, LLM models) are shared with the server: see app/core/yaml_configs.py.
"""

from __future__ import annotations

import os
from datetime import date
from functools import cached_property
from pathlib import Path

from pydantic import BaseModel, Field

from app.core.yaml_configs import (  # noqa: F401  (re-exported for research code)
    CONFIG_DIR,
    REPO_ROOT,
    Language,
    _load,
    load_models_config,
    load_sast_config,
)


def data_dir() -> Path:
    """Root of all benchmark data. Override with SECBENCH_DATA (e.g. a WSL ext4 path)."""
    return Path(os.environ.get("SECBENCH_DATA", str(REPO_ROOT / "data" / "bench"))).expanduser().resolve()


class Paths:
    """Well-known locations under the data directory."""

    def __init__(self, root: Path | None = None):
        self.root = root or data_dir()

    @cached_property
    def raw(self) -> Path:
        return self.root / "raw"

    @cached_property
    def repos(self) -> Path:
        return self.root / "repos"

    @cached_property
    def snapshots(self) -> Path:
        return self.root / "snapshots"

    @cached_property
    def benchmark(self) -> Path:
        return self.root / "benchmark.jsonl"

    @cached_property
    def candidates(self) -> Path:
        return self.root / "candidates.jsonl"

    @cached_property
    def sast(self) -> Path:
        return self.root / "sast"

    @cached_property
    def context(self) -> Path:
        return self.root / "context"

    @cached_property
    def llm_cache(self) -> Path:
        return self.root / "llm_cache"

    @cached_property
    def results(self) -> Path:
        return self.root / "results"

    @cached_property
    def work(self) -> Path:
        return self.root / "work"


# --------------------------------------------------------------------------- benchmark


class SecBenchJsSource(BaseModel):
    enabled: bool = True
    repo_url: str = "https://github.com/cristianstaicu/SecBench.js"


class OsvSource(BaseModel):
    enabled: bool = True
    ecosystems: list[str] = ["PyPI", "npm"]
    url_template: str = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
    min_published: date = date(2018, 1, 1)


class SimpleSource(BaseModel):
    enabled: bool = True


class Sources(BaseModel):
    patcheval: SimpleSource = SimpleSource()
    secbenchjs: SecBenchJsSource = SecBenchJsSource()
    pyvul: SimpleSource = SimpleSource()
    osv: OsvSource = OsvSource()


class TangledRule(BaseModel):
    max_files: int = 10
    max_changed_lines: int = 300


class Target(BaseModel):
    main_items: int = 120
    python_share: float = 0.5
    max_cwe_share: float = 0.25
    dev_size: int = 20
    post_cutoff_items: int = 30
    post_cutoff_max_cwe_share: float = 0.4
    extra_items: int = 30
    max_items_per_repo: int = 1
    max_source_files: int = 5000      # cheap pre-filter before checkout (tree listing only)
    # how many candidates to try (clone + diff) before giving up, per language
    max_attempts_per_language: int = 400


class BenchmarkConfig(BaseModel):
    seed: int = 13
    sources: Sources = Sources()
    cwe_whitelist: list[str]
    cwe_aliases: dict[str, str] = Field(default_factory=dict)
    loc_bounds: dict[str, tuple[int, int]]
    tangled: TangledRule = TangledRule()
    target: Target = Target()
    post_cutoff_date: date
    # filled from config/sast.yaml (shared product-code scope)
    path_excludes: list[str] = Field(default_factory=list)
    source_extensions: dict[str, list[str]] = Field(default_factory=dict)
    clone_timeout_s: int = 900
    workers: int = 8


# --------------------------------------------------------------------------- eval


class EvalConfig(BaseModel):
    line_tol: int = 5
    ks: list[int] = [1, 5, 10, 20]
    bootstrap_resamples: int = 10000
    max_function_lines: int | None = 300


# --------------------------------------------------------------------------- loading


def load_benchmark_config(path: Path | str = CONFIG_DIR / "benchmark.yaml") -> BenchmarkConfig:
    cfg = _load(path, BenchmarkConfig)
    if not cfg.path_excludes or not cfg.source_extensions:
        sast = load_sast_config()
        cfg.path_excludes = cfg.path_excludes or list(sast.path_excludes)
        cfg.source_extensions = cfg.source_extensions or dict(sast.source_extensions)
    return cfg


def load_eval_config(path: Path | str = CONFIG_DIR / "eval.yaml") -> EvalConfig:
    return _load(path, EvalConfig)
