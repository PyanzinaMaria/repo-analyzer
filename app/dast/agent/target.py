from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.dast.agent.config import PentestConfig
from app.dast.config import DastConfig
from app.dast.ssrf import DastTargetError, validate_target_url


@dataclass
class Response:
    url: str
    method: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed: float
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and 100 <= self.status < 600

    def snippet(self, limit: int = 300) -> str:
        body = (self.text or "").replace("\n", " ")[:limit]
        return f"{self.method} {self.url} -> {self.status} ({len(self.text)} bytes) {body}"


@dataclass
class Budget:
    max_requests: int
    max_seconds: int
    started: float = field(default_factory=time.perf_counter)
    requests: int = 0
    ok_responses: int = 0
    failed_requests: int = 0

    def can_request(self) -> bool:
        return (
            self.requests < self.max_requests
            and (time.perf_counter() - self.started) < self.max_seconds
        )

    @property
    def elapsed(self) -> float:
        return time.perf_counter() - self.started


class TargetClient:
    """HTTP client for the agent with SSRF policy, same-origin and rate limits."""

    def __init__(self, base_url: str, cfg: PentestConfig) -> None:
        self.cfg = cfg
        self.base_url = base_url.rstrip("/")
        dast_cfg = DastConfig(allow_private_targets=cfg.allow_private_targets)
        validate_target_url(self.base_url, dast_cfg)  # raises DastTargetError
        self.origin = self._origin(self.base_url)
        self.budget = Budget(cfg.max_requests, cfg.max_seconds)
        self.client = httpx.Client(
            timeout=cfg.request_timeout,
            follow_redirects=False,
            trust_env=False,  # never route localhost through a proxy
        )

    @staticmethod
    def _origin(url: str) -> tuple[str, str]:
        p = urlparse(url)
        return (p.scheme or "http").lower(), (p.hostname or "").lower()

    def same_origin(self, url: str) -> bool:
        return self._origin(url) == self.origin

    def absolute(self, url: str) -> str:
        return urljoin(self.base_url + "/", url)

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        allow_redirects: bool = False,
    ) -> Response:
        full = self.absolute(url)
        if not self.same_origin(full):
            raise DastTargetError(f"cross-origin request blocked: {full}")
        if not self.budget.can_request():
            raise RuntimeError("pentest budget exhausted (max_requests/max_seconds)")
        if self.cfg.delay_seconds:
            time.sleep(self.cfg.delay_seconds)
        self.budget.requests += 1
        t0 = time.perf_counter()
        try:
            resp = self.client.request(
                method.upper(),
                full,
                params=params,
                data=data,
                headers=headers,
                follow_redirects=allow_redirects,
            )
            self.budget.ok_responses += 1
            return Response(
                url=str(resp.request.url),
                method=method.upper(),
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                text=resp.text,
                elapsed=time.perf_counter() - t0,
            )
        except httpx.HTTPError as exc:
            self.budget.failed_requests += 1
            return Response(
                url=full, method=method.upper(), status=0, headers={}, text="",
                elapsed=time.perf_counter() - t0, error=str(exc),
            )

    def close(self) -> None:
        self.client.close()

    def stats(self) -> dict[str, Any]:
        return {
            "requests": self.budget.requests,
            "ok_responses": self.budget.ok_responses,
            "failed_requests": self.budget.failed_requests,
            "elapsed_seconds": round(self.budget.elapsed, 2),
        }
