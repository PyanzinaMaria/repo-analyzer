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
import re
import secrets
import shutil
import subprocess
import tempfile
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


def _containers_up(docker: str) -> set[str]:
    r = subprocess.run([docker, "ps", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=60)
    return set((r.stdout or "").split())


def _up_owasp(kind: str, cfg: DastBenchConfig, paths: Paths, state: dict,
              force: bool, summary: RunSummary | None) -> None:
    docker = _docker()
    spec = target_spec(cfg, kind)
    tid = f"{kind}-app"
    rec = state.get(tid) or {}
    if rec.get("status") == "up" and not force and spec.container in _containers_up(docker):
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


_DB_PORTS = {5432, 3306, 6379, 27017, 5984, 9092, 7687, 1433, 1521, 9200, 5601, 15672, 2181, 9042}

_JAVA_WAR_DOCKERFILE = """FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY . /src
# spotless needs a git repo, which the build context (a detached worktree) is not
RUN mvn -q -B clean package -DskipTests -Dspotless.skip=true

FROM tomcat:9.0-jdk17-temurin
COPY --from=build /src/target/*.war /usr/local/tomcat/webapps/
RUN cd /usr/local/tomcat/webapps && for f in *.war; do [ "$f" = "ROOT.war" ] || mv "$f" ROOT.war; done
EXPOSE {port}
CMD ["catalina.sh", "run"]
"""


def _sanitize_compose_envfiles(compose_file: Path) -> list[str]:
    """Create empty env_file targets referenced by a compose file but missing on disk
    (ancient pinned apps reference env files their setup scripts were supposed to write)."""
    import yaml

    created = []
    doc = yaml.safe_load(compose_file.read_text(encoding="utf-8")) or {}
    services = doc.get("services") or {}
    base = compose_file.parent
    for svc in services.values():
        if not isinstance(svc, dict):
            continue
        env = svc.get("env_file")
        entries = env if isinstance(env, list) else [env] if env else []
        for e in entries:
            p = base / str(e)
            if not p.is_file():
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("", encoding="utf-8")
                created.append(str(p))
    return created


def _boot_image_override(container: str, image: str, network: str, port: int,
                         cmd: list[str] | None, boot_timeout: int, out: dict) -> None:
    """Prebuilt community image: bypasses building ancient pinned commits entirely."""
    import httpx

    docker = shutil.which("docker")
    if not docker:
        out["ok"] = False
        out["reason"] = "docker not found on PATH"
        return
    run = subprocess.run(
        [docker, "run", "-d", "--name", container, "--network", network,
         "-p", f"127.0.0.1::{port}", image] + (cmd or []),
        capture_output=True, text=True, timeout=600)
    if run.returncode != 0:
        out["ok"] = False
        out["reason"] = f"docker run failed: {run.stderr[-400:]}"
        return
    published = subprocess.run([docker, "port", container, str(port)],
                               capture_output=True, text=True, timeout=60)
    line = (published.stdout or "").strip().splitlines()
    host_port = int(line[0].rsplit(":", 1)[1]) if line and ":" in line[0] else None
    if host_port is None:  # image may publish/serve a different port than requested
        listed = subprocess.run([docker, "port", container], capture_output=True,
                                text=True, timeout=60)
        for entry in (listed.stdout or "").splitlines():
            left, sep, right = entry.partition("->")
            if sep and right.strip():
                try:
                    host_port = int(right.strip().rsplit(":", 1)[1])
                    break
                except (ValueError, IndexError):
                    continue
    if host_port is None:
        state = subprocess.run([docker, "ps", "-a", "--filter", f"name={container}",
                                "--format", "{{.Status}}"], capture_output=True, text=True, timeout=60)
        logs = subprocess.run([docker, "logs", "--tail", "10", container],
                              capture_output=True, text=True, timeout=60)
        out["ok"] = False
        out["reason"] = (f"cannot resolve published port for {port}; container: "
                         f"{(state.stdout or '').strip()[:60]}; logs: "
                         f"{(logs.stdout or logs.stderr or '')[-200:]}")
        return
    host_url = f"http://127.0.0.1:{host_port}"
    deadline = time.monotonic() + boot_timeout
    while time.monotonic() < deadline:
        try:
            with httpx.Client(verify=False, timeout=5) as client:
                if client.get(host_url).status_code < 600:
                    break
        except httpx.HTTPError:
            pass
        time.sleep(2)
    else:
        logs = subprocess.run([docker, "logs", "--tail", "10", container],
                              capture_output=True, text=True, timeout=60)
        out["ok"] = False
        out["reason"] = (f"image {image} not ready after {boot_timeout}s on {port}; logs: "
                         f"{(logs.stdout or logs.stderr or '')[-200:]}")
        subprocess.run([docker, "rm", "-f", container], capture_output=True, timeout=60)
        return
    out.update(ok=True, host_url=host_url + "/", scan_url=f"http://{container}:{port}/",
               network=network, container=container,
               teardown={"method": "docker", "container": container, "image": image})


def _boot_java_war(root: Path, work_dir: Path, container: str, network: str, port: int,
                   boot_timeout: int, out: dict) -> None:
    """Maven WAR app -> tomcat:9 (java repos the sandbox has no runnable plan for)."""
    import httpx

    docker = shutil.which("docker")
    build_dir = work_dir / "realvuln" / container
    build_dir.mkdir(parents=True, exist_ok=True)
    (build_dir / "Dockerfile").write_text(_JAVA_WAR_DOCKERFILE.format(port=port), encoding="utf-8")
    tag = f"dast-bench:{container}"
    build = subprocess.run([docker, "build", "-f", str(build_dir / "Dockerfile"),
                            "-t", tag, str(root)], capture_output=True, text=True, timeout=3600)
    if build.returncode != 0:
        out["ok"] = False
        out["reason"] = f"java_war build failed: {(build.stderr or build.stdout)[-400:]}"
        return
    run = subprocess.run([docker, "run", "-d", "--name", container, "--network", network,
                          "-p", f"127.0.0.1::{port}", tag],
                         capture_output=True, text=True, timeout=120)
    if run.returncode != 0:
        out["ok"] = False
        out["reason"] = f"docker run failed: {run.stderr[-400:]}"
        return
    published = subprocess.run([docker, "port", container, str(port)],
                               capture_output=True, text=True, timeout=60)
    line = (published.stdout or "").strip().splitlines()
    host_port = int(line[0].rsplit(":", 1)[1]) if line and ":" in line[0] else None
    if host_port is None:
        out["ok"] = False
        out["reason"] = f"cannot resolve published port for {port}"
        return
    host_url = f"http://127.0.0.1:{host_port}"
    deadline = time.monotonic() + boot_timeout
    while time.monotonic() < deadline:
        try:
            with httpx.Client(verify=False, timeout=5) as client:
                if client.get(host_url).status_code < 600:
                    break
        except httpx.HTTPError:
            pass
        time.sleep(3)
    else:
        logs = subprocess.run([docker, "logs", "--tail", "10", container],
                              capture_output=True, text=True, timeout=60)
        out["ok"] = False
        out["reason"] = (f"image {image} not ready after {boot_timeout}s on {port}; logs: "
                         f"{(logs.stdout or logs.stderr or '')[-200:]}")
        subprocess.run([docker, "rm", "-f", container], capture_output=True, timeout=60)
        return
    out.update(ok=True, host_url=host_url + "/", scan_url=f"http://{container}:{port}/",
               network=network, container=container,
               teardown={"method": "docker", "container": container, "image": tag})


def _boot_compose_local(compose_file: Path, project: str, container: str, network: str,
                        port: int, boot_timeout: int, out: dict) -> None:
    """Bench-local `docker compose up` for compose items with a port override: picks the
    container that serves `port` (the sandbox picks the first published port, which is
    often the database), joins it to the shared network and waits for readiness."""
    import httpx

    docker = shutil.which("docker")
    up = subprocess.run([docker, "compose", "-f", str(compose_file), "-p", project,
                         "up", "-d", "--build"],
                        capture_output=True, text=True, timeout=boot_timeout)
    if up.returncode != 0:
        out["ok"] = False
        out["reason"] = f"docker compose up failed: {(up.stderr or up.stdout)[-400:]}"
        return
    ids = subprocess.run([docker, "compose", "-f", str(compose_file), "-p", project,
                          "ps", "-q"], capture_output=True, text=True, timeout=60)
    picked = None
    for cid in (ids.stdout or "").split():
        published = subprocess.run([docker, "port", cid.strip()], capture_output=True,
                                   text=True, timeout=60)
        for entry in (published.stdout or "").splitlines():
            left, sep, right = entry.partition("->")
            if not sep:
                continue
            try:
                c_port = int(left.split("/", 1)[0])
                h_port = int(right.strip().rsplit(":", 1)[1])
            except (ValueError, IndexError):
                continue
            if c_port == port and c_port not in _DB_PORTS:
                picked = (cid.strip(), h_port, c_port)
                break
        if picked:
            break
    if not picked:
        subprocess.run([docker, "compose", "-f", str(compose_file), "-p", project,
                        "down", "-v", "--remove-orphans"], capture_output=True, timeout=120)
        out["ok"] = False
        out["reason"] = f"compose started but no container serves port {port}"
        return
    cid, host_port, c_port = picked
    subprocess.run([docker, "network", "connect", network, cid], capture_output=True, timeout=60)
    cname = subprocess.run([docker, "inspect", cid, "--format", "{{index .Config.Labels \"com.docker.compose.service\"}}"],
                           capture_output=True, text=True, timeout=60).stdout.strip()
    scan_name = f"{project}-{cname or 'app'}-1"
    host_url = f"http://127.0.0.1:{host_port}"
    deadline = time.monotonic() + boot_timeout
    while time.monotonic() < deadline:
        try:
            with httpx.Client(verify=False, timeout=5) as client:
                if client.get(host_url).status_code < 600:
                    break
        except httpx.HTTPError:
            pass
        time.sleep(3)
    else:
        logs = subprocess.run([docker, "logs", "--tail", "10", cid],
                              capture_output=True, text=True, timeout=60)
        subprocess.run([docker, "compose", "-f", str(compose_file), "-p", project,
                        "down", "-v", "--remove-orphans"], capture_output=True, timeout=120)
        out["ok"] = False
        out["reason"] = (f"compose app not ready after {boot_timeout}s on {port}; logs: "
                         f"{(logs.stdout or logs.stderr or '')[-200:]}")
        return
    out.update(ok=True, host_url=host_url + "/", scan_url=f"http://{scan_name}:{c_port}/",
               network=network, container=cid,
               teardown={"method": "compose", "project": project,
                         "compose_file": str(compose_file), "container": cid})


def _boot_one(root_str: str, network: str, out_file: str,
              override_json: str = "{}", work_dir_str: str = "",
              boot_timeout: int = 900) -> None:
    """Child-process entry: boot one app (sandbox / prebuilt image / java_war / compose)
    and dump the record as JSON. CWD is switched to the app root so compose `include:`
    rebasing and relative env_file paths land inside the snapshot."""
    import json as _json
    import os

    import httpx

    import app.sandbox.runner as sandbox_runner
    from app.sandbox.config import SandboxConfig
    from app.sandbox.detect import detect_run_plan

    override = _json.loads(override_json) if override_json else {}
    root = Path(root_str)
    token = secrets.token_hex(5)
    try:
        os.chdir(root)
        if override.get("image"):
            out = {}
            _boot_image_override(f"ra-dast-{token}", override["image"], network,
                                 int(override.get("port") or 8000), override.get("cmd"),
                                 override.get("boot_timeout_s") or boot_timeout, out)
            Path(out_file).write_text(_json.dumps(out, ensure_ascii=False), encoding="utf-8")
            return
        if override.get("java_war"):
            out = {}
            _boot_java_war(root, Path(work_dir_str) if work_dir_str else Path(tempfile.gettempdir()),
                           f"ra-dast-{token}", network, int(override.get("port") or 8080),
                           override.get("boot_timeout_s") or boot_timeout, out)
            Path(out_file).write_text(_json.dumps(out, ensure_ascii=False), encoding="utf-8")
            return

        # bench-local patches (the product sandbox keeps its own defaults):
        # 1) compose readiness must not land on a database port
        _orig_published = sandbox_runner._published_port

        def _published_port_skip_db(docker: str, container: str) -> tuple[int, int]:
            listed = sandbox_runner._run([docker, "port", container])
            pairs = []
            for line in (listed.stdout or "").splitlines():
                left, sep, right = line.partition("->")
                if not sep or not left.strip().endswith("/tcp"):
                    continue
                try:
                    pairs.append((int(right.strip().rsplit(":", 1)[1]),
                                  int(left.split("/", 1)[0])))
                except (ValueError, IndexError):
                    continue
            for h, c in pairs:
                if c not in _DB_PORTS:
                    return h, c
            return pairs[0] if pairs else (0, 0)

        sandbox_runner._published_port = _published_port_skip_db

        plan = detect_run_plan(root)
        if plan is None:
            raise RuntimeError("no runnable web target detected")
        if override.get("port"):
            plan.port = int(override["port"])
        if plan.method == "compose" and plan.compose_file and Path(plan.compose_file).is_file():
            _sanitize_compose_envfiles(Path(plan.compose_file))
        if plan.method == "compose" and override.get("port") and plan.compose_file:
            # the sandbox picks the first published port (often a database); drive
            # compose directly and select the container that serves the override port
            out = {}
            _boot_compose_local(Path(plan.compose_file), f"ra{token}", f"ra-dast-{token}",
                                network, int(override["port"]), boot_timeout, out)
            Path(out_file).write_text(_json.dumps(out, ensure_ascii=False), encoding="utf-8")
            return
        session = sandbox_runner.start_sandbox(root, cfg=SandboxConfig(network=network,
                                                        boot_timeout_seconds=boot_timeout),
                                plan=plan)
        sandbox_runner._published_port = _orig_published
        plan = session.plan
        teardown = {"method": plan.method, "container": session.container_name,
                    "image": session.meta.get("image")}
        if plan.method == "compose":
            teardown.update(compose_file=str(session.meta.get("compose_file") or plan.compose_file),
                            project=str(session.meta.get("project") or ""))
        rec = {"ok": True, "host_url": session.host_url, "scan_url": session.network_url,
               "network": session.network, "container": session.container_name,
               "teardown": teardown}
    except BaseException as exc:  # noqa: BLE001 - the child reports any failure as data
        rec = {"ok": False, "reason": str(exc)[:500]}
    Path(out_file).write_text(_json.dumps(rec, ensure_ascii=False), encoding="utf-8")


def _up_realvuln(cfg: DastBenchConfig, paths: Paths, state: dict,
                 force: bool, summary: RunSummary | None) -> None:
    """One app per bounded child process: a stuck npm/compose boot must not block
    the other items (the sandbox build/readiness caps are configurable, but ancient
    pinned apps still hang sometimes)."""
    import json as _json
    import multiprocessing
    import time

    docker = _docker()
    boot_timeout = cfg.boot_timeout_s
    watchdog = cfg.watchdog_timeout_s
    worktrees = _realvuln_worktrees(paths)
    summary = summary or RunSummary("dast up realvuln")
    boot_dir = paths.dast / "_boot"
    boot_dir.mkdir(parents=True, exist_ok=True)
    for tid, root in sorted(worktrees.items()):
        rec = state.get(tid) or {}
        if rec.get("status") == "up" and not force \
                and rec.get("container") in _containers_up(docker):
            log.info("%s: already up at %s", tid, rec.get("host_url"))
            continue
        if not root.is_dir():
            state[tid] = {"kind": "realvuln", "status": "boot_failed",
                          "reason": f"snapshot worktree missing: {root.name}"}
            _write(paths, state)
            summary.fail(f"{tid}: worktree missing")
            continue
        override = cfg.realvuln_overrides.get(tid)
        boot_for_item = (override.boot_timeout_s if override and override.boot_timeout_s
                         else boot_timeout)
        out = boot_dir / f"{tid}.json"
        out.unlink(missing_ok=True)
        proc = multiprocessing.Process(
            target=_boot_one,
            args=(str(root), cfg.network, str(out),
                  override.model_dump_json() if override else "{}",
                  str(paths.work), boot_for_item),
            daemon=True)
        started = time.monotonic()
        proc.start()
        proc.join(watchdog)
        if proc.is_alive():
            proc.kill()
            proc.join(10)
            result = {"ok": False, "reason": f"boot exceeded {watchdog}s (killed)"}
        else:
            result = _json.loads(out.read_text(encoding="utf-8")) if out.is_file() else \
                {"ok": False, "reason": "boot child produced no result"}
        if not result.get("ok"):
            state[tid] = {"kind": "realvuln", "status": "boot_failed",
                          "reason": result.get("reason", "?")}
            _write(paths, state)
            summary.fail(f"{tid}: {result.get('reason', '?')[:90]}")
            continue
        state[tid] = {"kind": "realvuln", "status": "up", "host_url": result["host_url"],
                      "scan_url": result["scan_url"], "network": result["network"],
                      "spec_path": None, "container": result["container"],
                      "boot_seconds": round(time.monotonic() - started, 1),
                      "teardown": result["teardown"]}
        _write(paths, state)
        summary.inc("targets up")
        log.info("%s: %s (%s)", tid, result["host_url"], result["teardown"].get("method"))


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


def _sweep_orphan_sandboxes(docker: str, summary: RunSummary) -> None:
    """Compose projects left over by killed boots (sandbox projects are named ra<token>)."""
    listed = subprocess.run([docker, "ps", "-a", "--format",
                             "{{.Label \"com.docker.compose.project\"}}"],
                            capture_output=True, text=True, timeout=60)
    projects = {line.strip() for line in (listed.stdout or "").splitlines()
                if re.fullmatch(r"ra[0-9a-f]{10}", line.strip())}
    for project in sorted(projects):
        subprocess.run([docker, "compose", "-p", project, "down", "-v", "--remove-orphans"],
                       capture_output=True, timeout=120)
        summary.inc("orphan compose swept")


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
    if kind == "realvuln":
        _sweep_orphan_sandboxes(docker, summary)
    _write(paths, state)
