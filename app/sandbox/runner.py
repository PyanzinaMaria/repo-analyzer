from __future__ import annotations

import logging
import shutil
import subprocess
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import httpx

from app.sandbox.config import SandboxConfig, get_sandbox_config
from app.sandbox.detect import detect_run_plan
from app.sandbox.dockerfile_gen import write_heuristic_dockerfile
from app.sandbox.models import RunPlan, SandboxSession
from app.languages.registry import LanguageRegistry

logger = logging.getLogger(__name__)


class SandboxError(RuntimeError):
    """Sandbox boot / lifecycle failure."""


def _run(cmd: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    logger.debug("sandbox exec: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _ensure_docker() -> str:
    docker = shutil.which("docker")
    if not docker:
        raise SandboxError("docker not found on PATH")
    return docker


def _ensure_network(docker: str, network: str) -> None:
    listed = _run([docker, "network", "ls", "--format", "{{.Name}}"])
    names = {line.strip() for line in (listed.stdout or "").splitlines()}
    if network not in names:
        created = _run([docker, "network", "create", network])
        if created.returncode != 0 and network not in (
            _run([docker, "network", "ls", "--format", "{{.Name}}"]).stdout or ""
        ):
            raise SandboxError(f"cannot create docker network {network}: {created.stderr}")


def _parse_host_port(docker: str, container: str, container_port: int) -> int:
    probe = _run([docker, "port", container, str(container_port)])
    if probe.returncode != 0 or not (probe.stdout or "").strip():
        raise SandboxError(f"cannot resolve published port: {probe.stderr}")
    # e.g. 127.0.0.1:54321
    last = (probe.stdout or "").strip().splitlines()[-1]
    host_port = last.rsplit(":", 1)[-1].strip()
    return int(host_port)


def _wait_http(url: str, *, timeout_seconds: int) -> None:
    deadline = time.time() + timeout_seconds
    last_err = "no attempt"
    while time.time() < deadline:
        try:
            with httpx.Client(follow_redirects=True, timeout=3.0) as client:
                resp = client.get(url)
                if resp.status_code < 500:
                    return
                last_err = f"status={resp.status_code}"
        except httpx.HTTPError as exc:
            last_err = str(exc)
        time.sleep(1.5)
    raise SandboxError(f"target not ready at {url} within {timeout_seconds}s ({last_err})")


def _guess_dockerfile_port(dockerfile: Path, default: int = 8000) -> int:
    try:
        text = dockerfile.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return default
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("EXPOSE"):
            parts = stripped.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return default


def _build_and_run_image(
    docker: str,
    plan: RunPlan,
    cfg: SandboxConfig,
    *,
    dockerfile: Path,
    image_tag: str,
    container_name: str,
) -> SandboxSession:
    build = _run(
        [
            docker,
            "build",
            "-f",
            str(dockerfile),
            "-t",
            image_tag,
            str(plan.context_dir),
        ],
        timeout=max(cfg.boot_timeout_seconds, 300),
    )
    if build.returncode != 0:
        raise SandboxError(f"docker build failed: {(build.stderr or build.stdout)[-2000:]}")

    run = _run(
        [
            docker,
            "run",
            "-d",
            "--name",
            container_name,
            "--network",
            cfg.network,
            "--memory",
            cfg.memory,
            "--cpus",
            cfg.cpus,
            "-p",
            f"{cfg.publish_host}:0:{plan.port}",
            image_tag,
        ],
        timeout=60,
    )
    if run.returncode != 0:
        raise SandboxError(f"docker run failed: {(run.stderr or run.stdout)[-2000:]}")

    host_port = _parse_host_port(docker, container_name, plan.port)
    host_url = f"http://{cfg.publish_host}:{host_port}{plan.health_path if plan.health_path.startswith('/') else '/' + plan.health_path}"
    # Wait on root-ish URL for readiness (health_path may 404 for some apps)
    ready_url = f"http://{cfg.publish_host}:{host_port}/"
    _wait_http(ready_url, timeout_seconds=cfg.boot_timeout_seconds)
    network_url = f"http://{container_name}:{plan.port}/"
    return SandboxSession(
        container_name=container_name,
        network=cfg.network,
        host_url=f"http://{cfg.publish_host}:{host_port}/",
        network_url=network_url,
        plan=plan,
        meta={
            "method": plan.method,
            "image": image_tag,
            "host_port": host_port,
            "ready_url": ready_url,
            "health_url": host_url,
            "framework": plan.framework,
            "entry": plan.entry,
        },
    )


def _run_compose(
    docker: str,
    plan: RunPlan,
    cfg: SandboxConfig,
    *,
    project_name: str,
) -> SandboxSession:
    if plan.compose_file is None:
        raise SandboxError("compose plan missing compose_file")
    compose_file = plan.compose_file
    up = _run(
        [
            docker,
            "compose",
            "-f",
            str(compose_file),
            "-p",
            project_name,
            "up",
            "-d",
            "--build",
        ],
        timeout=max(cfg.boot_timeout_seconds, 300),
    )
    if up.returncode != 0:
        raise SandboxError(f"docker compose up failed: {(up.stderr or up.stdout)[-2000:]}")

    # Discover first published http-ish port from `docker compose ps`
    ps = _run(
        [
            docker,
            "compose",
            "-f",
            str(compose_file),
            "-p",
            project_name,
            "ps",
            "--format",
            "{{.Name}} {{.Publishers}}",
        ]
    )
    container_name = ""
    host_port = 0
    for line in (ps.stdout or "").splitlines():
        parts = line.strip().split(maxsplit=1)
        if not parts:
            continue
        container_name = parts[0]
        # Try docker port on common ports
        for candidate in (plan.port, 8000, 5000, 3000, 8080):
            try:
                host_port = _parse_host_port(docker, container_name, candidate)
                plan.port = candidate
                break
            except SandboxError:
                continue
        if host_port:
            break

    if not container_name or not host_port:
        raise SandboxError("compose started but no published port discovered")

    # Connect container to sandbox network for ZAP
    _run([docker, "network", "connect", cfg.network, container_name])

    ready_url = f"http://{cfg.publish_host}:{host_port}/"
    _wait_http(ready_url, timeout_seconds=cfg.boot_timeout_seconds)
    return SandboxSession(
        container_name=container_name,
        network=cfg.network,
        host_url=ready_url,
        network_url=f"http://{container_name}:{plan.port}/",
        plan=plan,
        meta={
            "method": "compose",
            "compose_file": str(compose_file),
            "project": project_name,
            "host_port": host_port,
        },
    )


def start_sandbox(
    root: Path,
    *,
    cfg: SandboxConfig | None = None,
    registry: LanguageRegistry | None = None,
    plan: RunPlan | None = None,
) -> SandboxSession:
    """Build and start a sandbox target. Caller must stop_sandbox()."""
    cfg = cfg or get_sandbox_config()
    if not cfg.enabled:
        raise SandboxError("sandbox.enabled is false")

    docker = _ensure_docker()
    _ensure_network(docker, cfg.network)

    resolved = plan or detect_run_plan(root, registry=registry)
    if resolved is None:
        raise SandboxError("no runnable web target detected")

    token = uuid.uuid4().hex[:10]
    container_name = f"ra-dast-{token}"
    image_tag = resolved.image_tag or f"repo-analyzer-dast:{token}"
    generated_dockerfile: Path | None = None

    try:
        if resolved.method == "compose":
            return _run_compose(docker, resolved, cfg, project_name=f"ra{token}")

        if resolved.method == "dockerfile":
            dockerfile = resolved.dockerfile or (resolved.context_dir / "Dockerfile")
            resolved.port = _guess_dockerfile_port(dockerfile, resolved.port)
            return _build_and_run_image(
                docker,
                resolved,
                cfg,
                dockerfile=dockerfile,
                image_tag=image_tag,
                container_name=container_name,
            )

        # heuristic
        generated_dockerfile = write_heuristic_dockerfile(resolved, cfg)
        resolved.dockerfile = generated_dockerfile
        session = _build_and_run_image(
            docker,
            resolved,
            cfg,
            dockerfile=generated_dockerfile,
            image_tag=image_tag,
            container_name=container_name,
        )
        session.meta["generated_dockerfile"] = str(generated_dockerfile)
        return session
    except Exception:
        # Best-effort cleanup of partial boot
        _run([docker, "rm", "-f", container_name])
        _run([docker, "rmi", "-f", image_tag])
        if generated_dockerfile and generated_dockerfile.exists():
            generated_dockerfile.unlink(missing_ok=True)
        raise


def stop_sandbox(session: SandboxSession, *, cfg: SandboxConfig | None = None) -> None:
    cfg = cfg or get_sandbox_config()
    docker = shutil.which("docker")
    if not docker:
        return
    meta = session.meta or {}
    if session.plan.method == "compose" and meta.get("compose_file"):
        _run(
            [
                docker,
                "compose",
                "-f",
                str(meta["compose_file"]),
                "-p",
                str(meta.get("project") or "ra"),
                "down",
                "-v",
                "--remove-orphans",
            ],
            timeout=120,
        )
    else:
        _run([docker, "rm", "-f", session.container_name], timeout=60)
        image = meta.get("image")
        if image:
            _run([docker, "rmi", "-f", str(image)], timeout=60)
    generated = meta.get("generated_dockerfile")
    if generated:
        Path(str(generated)).unlink(missing_ok=True)


@contextmanager
def sandbox_session(
    root: Path,
    *,
    cfg: SandboxConfig | None = None,
    registry: LanguageRegistry | None = None,
) -> Iterator[SandboxSession]:
    session = start_sandbox(root, cfg=cfg, registry=registry)
    try:
        yield session
    finally:
        try:
            stop_sandbox(session, cfg=cfg)
        except Exception:  # noqa: BLE001
            logger.exception("sandbox cleanup failed for %s", session.container_name)
