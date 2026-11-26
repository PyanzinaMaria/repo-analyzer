from __future__ import annotations

"""Unified security pipeline.

Stages:
  1. code review (agentic LLM or deterministic)  -> VulnHypothesis
  2. hypothesis normalisation + risk scoring
  3. dynamic verification (plugins x strategies) -> Verdict + evidence
  4. LLM-as-judge on detector matches            -> false-positive filter
  5. reports: Markdown / JSON / SARIF

The pipeline finds *general* web vulnerabilities (CWE-89/79/22/78/611/918/601/502/798),
not only LLM-specific risks, and accepts hypotheses from any source: SAST,
LLM review, and (in the future) the RL threat-maximisation agent.
"""

__all__ = ["__version__"]
__version__ = "0.1.0"
