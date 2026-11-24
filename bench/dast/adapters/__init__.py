"""DAST tool registry. Each module exposes run(target, out_dir, cfg) -> (DastToolResult, findings)."""

from __future__ import annotations

from bench.dast.adapters import nikto, nuclei, offat, wapiti, zap

DAST_TOOLS = {"zap": zap, "wapiti": wapiti, "nuclei": nuclei, "offat": offat, "nikto": nikto}
