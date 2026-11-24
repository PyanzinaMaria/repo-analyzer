"""Live target lifecycle for the DAST benchmark: `bench dast up|down <kind>`.

owasp-java  -> two-stage docker build (maven -> Tomcat 9, HTTPS :8443, repo .keystore)
owasp-python -> slim docker image (flask + ldap3), `flask run --host 0.0.0.0` :5000
realvuln    -> per-item boot through the product sandbox runner (compose/Dockerfile/heuristic)

State lives in <data>/dast/targets.json; records carry host_url (native tools) and scan_url
(container-DNS URL for dockerized tools on the shared network) plus teardown info. OWASP
images are kept after `down` (they cost a one-off maven build); sandbox images are removed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

import httpx

from app.core import io
from app.core.runlog import RunSummary, log
from bench.config import Paths
from bench.dast.config import DastBenchConfig, target_spec
from bench.dast.openapi import discover_routes, routes_to_openapi, write_spec
from bench.external import _group_id

STATE_FILE = "targets.json"

_SERVER_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Server port="8005" shutdown="SHUTDOWN">
  <GlobalNamingResources>
    <Resource name="UserDatabase" auth="Container" type="org.apache.catalina.UserDatabase"
              factory="org.apache.catalina.users.MemoryUserDatabaseFactory"
              pathname="conf/tomcat-users.xml"/>
  </GlobalNamingResources>
  <Service name="Catalina">
    <Connector port="8080" protocol="HTTP/1.1" connectionTimeout="20000"/>
    <Connector port="{port}" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="200" SSLEnabled="true" scheme="https" secure="true">
      <SSLHostConfig>
        <Certificate certificateKeystoreFile="conf/.keystore"
                     certificateKeystorePassword="changeit" type="RSA"/>
      </SSLHostConfig>
    </Connector>
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps" unpackWARs="true" autoDeploy="false"/>
    </Engine>
  </Service>
</Server>
"""

JAVA_DOCKERFILE = """FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY . /src
# spotless needs a git repo, which the build context (a detached worktree) is not
RUN mvn -q -B clean package -DskipTests -Dspotless.skip=true

FROM tomcat:9.0-jdk17-temurin
COPY --from=build /src/target/benchmark.war /usr/local/tomcat/webapps/ROOT.war
COPY --from=build /src/.keystore /usr/local/tomcat/conf/.keystore
# bench = second build context (paths.work/dast/owasp-java, see --build-context below)
COPY --from=bench server.xml /usr/local/tomcat/conf/server.xml
EXPOSE {port}
CMD ["catalina.sh", "run"]
"""

PYTHON_DOCKERFILE = """FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir flask==3.1.0 ldap3
EXPOSE {port}
CMD ["flask", "--app", "app", "run", "--host", "0.0.0.0", "--port", "{port}"]
"""

DOCKERIGNORE = """.git
"""


# --------------------------------------------------------------------------- state


def _read(paths: Paths) -> dict:
    f = paths.dast / STATE_FILE
    return io.read_json(f) if f.is_file() else {}


def _write(paths: Paths, state: dict) -> None:
    paths.dast.mkdir(parents=True, exist_ok=True)
    (paths.dast / STATE_FILE).write_text(
        json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def owasp_worktree(paths: Paths, kind: str) -> Path:
    """Snapshot worktree of the pinned OWASP repo (all items share one repo+commit)."""
    items = io.read_jsonl(paths.benchmark)
    if not items:
        raise SystemExit(f"{kind}: benchmark.jsonl is empty (run bench external build {kind})")
    first = items[0]
    return paths.snapshots / "_groups" / _group_id(first["repo_url"], first["vuln_commit"])


def _docker() -> str:
    docker = shutil.which("docker")
    if not docker:
        raise SystemExit("docker not found on PATH")
    return docker


def _wait_ready(url: str, timeout_s: int) -> float:
    """Any HTTP answer counts as ready (even 4xx/5xx); TLS verification is off (self-signed)."""
    started = time.monotonic()
    deadline = started + timeout_s
    while time.monotonic() < deadline:
        try:
            with httpx.Client(verify=False, timeout=5) as client:
                r = client.get(url)
            if r.status_code < 600:
                return time.monotonic() - started
        except httpx.HTTPError:
            pass
        time.sleep(2)
    raise TimeoutError(f"target not ready after {timeout_s}s: {url}")


# --------------------------------------------------------------------------- owasp targets


def _build_owasp(kind: str, spec, worktree: Path, paths: Paths, docker: str, force: bool) -> str:
    if not worktree.is_dir():
        raise SystemExit(f"{kind}: snapshot worktree missing: {worktree}")
    build_dir = paths.work / "dast" / kind
    build_dir.mkdir(parents=True, exist_ok=True)
    if kind == "owasp-java":
        (build_dir / "server.xml").write_text(_SERVER_XML.format(port=spec.port), encoding="utf-8")
        text = JAVA_DOCKERFILE.format(port=spec.port)
    else:
        text = PYTHON_DOCKERFILE.format(port=spec.port)
    (build_dir / "Dockerfile").write_text(text, encoding="utf-8")
    (build_dir / ".dockerignore").write_text(DOCKERIGNORE, encoding="utf-8")
    if force or subprocess.run([docker, "image", "inspect", spec.image],
                               capture_output=True).returncode != 0:
        log.info("building %s from %s (one-off; the java image takes ~20-40 min)", spec.image, worktree)
        r = subprocess.run([docker, "build", "-f", str(build_dir / "Dockerfile"),
                            "--build-context", f"bench={build_dir}",
                            "-t", spec.image, str(worktree)], timeout=7200)
        if r.returncode != 0:
            raise SystemExit(f"{kind}: docker build failed (rc={r.returncode})")
    return spec.image


def _up_owasp(kind: str, cfg: DastBenchConfig, paths: Paths, state: dict,
              force: bool, summary: RunSummary | None) -> None:
    docker = _docker()
    spec = target_spec(cfg, kind)
    tid = f"{kind}-app"
    rec = state.get(tid) or {}
    if rec.get("status") == "up" and not force:
        log.info("%s: already up at %s", tid, rec.get("host_url"))
        return
    worktree = owasp_worktree(paths, kind)
    image = _build_owasp(kind, spec, worktree, paths, docker, force)
    subprocess.run([docker, "rm", "-f", spec.container], capture_output=True)
    host_url = f"{spec.scheme}://127.0.0.1:{spec.port}"
    r = subprocess.run([docker, "run", "-d", "--name", spec.container,
                        "--network", cfg.network,
                        "-p", f"127.0.0.1:{spec.port}:{spec.port}", image],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"{kind}: docker run failed: {r.stderr[-500:]}")
    try:
        boot = _wait_ready(host_url, cfg.boot_timeout_s)
    except Exception as exc:  # noqa: BLE001 - record and keep the container for debugging
        state[tid] = {"kind": kind, "status": "boot_failed", "reason": str(exc)[:500],
                      "host_url": host_url, "container": spec.container, "image": image}
        _write(paths, state)
        (summary or RunSummary(f"dast up {kind}")).fail(f"{tid}: {str(exc)[:100]}")
        return
    spec_path = None
    routes = discover_routes(worktree, kind)
    if routes:
        doc = routes_to_openapi(routes, title=f"{kind} (generated from pinned routes)")
        spec_path = str(write_spec(doc, paths.dast / tid / "openapi.json"))
    state[tid] = {"kind": kind, "status": "up", "host_url": host_url,
                  "scan_url": f"{spec.scheme}://{spec.container}:{spec.port}",
                  "network": cfg.network, "container": spec.container, "image": image,
                  "spec_path": spec_path, "boot_seconds": round(boot, 1),
                  "routes": len(routes),
                  "teardown": {"method": "docker", "container": spec.container}}
    _write(paths, state)
    if summary:
        summary.inc("targets up")
        summary.note(f"{tid}: {host_url} (boot {boot:.0f}s, {len(routes)} routes -> OpenAPI for OFFAT)")


# --------------------------------------------------------------------------- realvuln


def _realvuln_worktrees(paths: Paths) -> dict[str, Path]:
    """item id -> pinned worktree (snapshots/_groups/<repo__sha>)."""
    out = {}
    for row in io.read_jsonl(paths.benchmark):
        out[row["id"]] = paths.snapshots / "_groups" / _group_id(row["repo_url"], row["vuln_commit"])
    return out


def _up_realvuln(cfg: DastBenchConfig, paths: Paths, state: dict,
                 force: bool, summary: RunSummary | None) -> None:
    from app.sandbox.config import SandboxConfig
    from app.sandbox.runner import start_sandbox

    worktrees = _realvuln_worktrees(paths)
    summary = summary or RunSummary("dast up realvuln")
    for tid, root in sorted(worktrees.items()):
        rec = state.get(tid) or {}
        if rec.get("status") == "up" and not force:
            log.info("%s: already up at %s", tid, rec.get("host_url"))
            continue
        if not root.is_dir():
            state[tid] = {"kind": "realvuln", "status": "boot_failed",
                          "reason": f"snapshot worktree missing: {root.name}"}
            _write(paths, state)
            summary.fail(f"{tid}: worktree missing")
            continue
        try:
            session = start_sandbox(root, cfg=SandboxConfig(network=cfg.network))
        except Exception as exc:  # noqa: BLE001 - soft-fail per item, keep going
            state[tid] = {"kind": "realvuln", "status": "boot_failed", "reason": str(exc)[:500]}
            _write(paths, state)
            summary.fail(f"{tid}: {str(exc)[:100]}")
            continue
        plan = session.plan
        teardown = {"method": plan.method, "container": session.container_name,
                    "image": session.meta.get("image")}
        if plan.method == "compose":
            teardown.update(compose_file=str(session.meta.get("compose_file") or plan.compose_file),
                            project=str(session.meta.get("project") or ""))
        state[tid] = {"kind": "realvuln", "status": "up", "host_url": session.host_url,
                      "scan_url": session.network_url, "network": session.network,
                      "spec_path": None, "container": session.container_name,
                      "teardown": teardown}
        _write(paths, state)
        summary.inc("targets up")
        log.info("%s: %s (%s)", tid, session.host_url, plan.method)


# --------------------------------------------------------------------------- commands


def up(kind: str, cfg: DastBenchConfig, paths: Paths | None = None,
       force: bool = False, summary: RunSummary | None = None) -> None:
    paths = paths or Paths()
    state = _read(paths)
    if kind == "realvuln":
        _up_realvuln(cfg, paths, state, force, summary)
    elif kind in ("owasp-java", "owasp-python"):
        _up_owasp(kind, cfg, paths, state, force, summary)
    else:
        raise SystemExit(f"unknown kind {kind!r} (owasp-java|owasp-python|realvuln)")


def down(kind: str, paths: Paths | None = None, summary: RunSummary | None = None) -> None:
    paths = paths or Paths()
    state = _read(paths)
    docker = _docker()
    summary = summary or RunSummary(f"dast down {kind}")
    for tid, rec in sorted(state.items()):
        if rec.get("kind") != kind or rec.get("status") != "up":
            continue
        td = rec.get("teardown") or {}
        if td.get("method") == "compose" and td.get("compose_file"):
            subprocess.run([docker, "compose", "-f", td["compose_file"], "-p",
                            td.get("project") or "ra", "down", "-v", "--remove-orphans"],
                           capture_output=True, timeout=120)
        else:
            subprocess.run([docker, "rm", "-f", td.get("container") or rec.get("container")],
                           capture_output=True, timeout=60)
            image = td.get("image")
            # OWASP images are expensive one-off builds: keep them, drop generated sandbox images.
            if image and image.startswith("repo-analyzer-dast:"):
                subprocess.run([docker, "rmi", "-f", image], capture_output=True, timeout=60)
        rec["status"] = "down"
        summary.inc("targets down")
    _write(paths, state)
