from __future__ import annotations

from pathlib import Path

from app.sandbox.config import SandboxConfig
from app.sandbox.models import RunPlan


def render_heuristic_dockerfile(plan: RunPlan, cfg: SandboxConfig) -> str:
    """Generate a Dockerfile that installs deps and runs the detected CMD."""
    req_line = ""
    if plan.requirements_file:
        req_line = (
            f"COPY {plan.requirements_file} /tmp/requirements.txt\n"
            "RUN pip install --no-cache-dir -r /tmp/requirements.txt\n"
        )
    else:
        # Minimal web stack fallbacks
        if plan.framework == "fastapi":
            req_line = "RUN pip install --no-cache-dir fastapi uvicorn\n"
        elif plan.framework == "flask":
            req_line = "RUN pip install --no-cache-dir flask\n"
        elif plan.framework == "django":
            req_line = "RUN pip install --no-cache-dir django\n"

    cmd_json = ", ".join(f'"{part}"' for part in plan.cmd)
    return (
        f"FROM {cfg.base_image}\n"
        "WORKDIR /app\n"
        f"{req_line}"
        "COPY . /app\n"
        f"EXPOSE {plan.port}\n"
        f"CMD [{cmd_json}]\n"
    )


def write_heuristic_dockerfile(plan: RunPlan, cfg: SandboxConfig) -> Path:
    path = plan.context_dir / ".repo-analyzer.Dockerfile"
    path.write_text(render_heuristic_dockerfile(plan, cfg), encoding="utf-8")
    return path
