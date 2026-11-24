"""Thin httpx wrapper for executing actions against a live target."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from .actions import Action


@dataclass
class Observation:
    url: str
    status_code: int
    headers: Any
    html: str
    page_path: str
    submitted_values: tuple[str, ...] = ()


class LiveClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 15.0,
        start_path: str = "/",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.start_path = start_path or "/"
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "live-test-runner/0.1"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "LiveClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def wait_ready(self, attempts: int = 60) -> None:
        import time

        last: Exception | None = None
        probes = ("/health", self.start_path, "/")
        for _ in range(attempts):
            for path in probes:
                try:
                    response = self._client.get(path)
                    if response.status_code < 500:
                        return
                except httpx.HTTPError as exc:
                    last = exc
            time.sleep(1.0)
        raise RuntimeError(f"Target not ready at {self.base_url}: {last}")

    def reset(self) -> Observation:
        """Clear session and open the configured start page."""
        self._client.cookies.clear()
        response = self._client.get(self.start_path)
        return self._observe(response, self.start_path.split("?", 1)[0] or "/")

    def get(self, path: str) -> Observation:
        response = self._client.get(path)
        return self._observe(response, path.split("?", 1)[0] or "/")

    def execute(self, action: Action) -> Observation:
        path = action.path or self.start_path
        if action.method == "GET":
            if action.fields:
                # Rare: GET form with fields — append as query.
                query = "&".join(f"{k}={v}" for k, v in action.fields)
                sep = "&" if "?" in path else "?"
                path = f"{path}{sep}{query}" if query else path
            response = self._client.get(path)
            values = tuple(v for _, v in action.fields)
            if "q=" in path:
                values = values + tuple(parse_qs(urlparse(path).query).get("q", []))
            return self._observe(response, path.split("?", 1)[0] or "/", values)
        data = {key: value for key, value in action.fields}
        response = self._client.post(path, data=data)
        return self._observe(
            response,
            path.split("?", 1)[0] or "/",
            tuple(data.values()),
        )

    def absolute(self, path: str) -> str:
        return urljoin(self.base_url + "/", path.lstrip("/"))

    @staticmethod
    def _observe(
        response: httpx.Response,
        page_path: str,
        submitted_values: tuple[str, ...] = (),
    ) -> Observation:
        final_path = urlparse(str(response.url)).path or page_path or "/"
        return Observation(
            url=str(response.url),
            status_code=response.status_code,
            headers=response.headers,
            html=response.text,
            page_path=final_path,
            submitted_values=submitted_values,
        )
