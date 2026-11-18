"""Docker sandbox: auto-boot web targets for unified SAST+DAST scans."""

from app.sandbox.config import SandboxConfig, get_sandbox_config
from app.sandbox.models import RunPlan, SandboxSession

__all__ = [
    "RunPlan",
    "SandboxConfig",
    "SandboxError",
    "SandboxSession",
    "detect_run_plan",
    "get_sandbox_config",
    "sandbox_session",
    "start_sandbox",
    "stop_sandbox",
]


def __getattr__(name: str):
    if name == "detect_run_plan":
        from app.sandbox.detect import detect_run_plan

        return detect_run_plan
    if name in {"start_sandbox", "stop_sandbox", "sandbox_session", "SandboxError"}:
        from app.sandbox import runner as _runner

        return getattr(_runner, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
