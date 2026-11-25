from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    kind: str = "query"          # query | form | path
    source: str = "crawl"

    def describe(self) -> str:
        params = ",".join(sorted(self.params)) or "-"
        return f"{self.method} {self.url} [{self.kind}:{params}]"


class _LinkFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {
                "action": a.get("action") or "",
                "method": (a.get("method") or "get").upper(),
                "inputs": [],
            }
        elif tag in {"input", "textarea", "select"} and self._form is not None:
            name = a.get("name")
            if name:
                self._form["inputs"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


_SKIP_EXT = re.compile(r"\.(png|jpe?g|gif|svg|css|js|ico|woff2?|ttf|map|zip|pdf)$", re.I)


def discover(client, *, max_pages: int = 8, max_params: int = 12) -> tuple[list[str], list[Endpoint]]:
    """Fetch the root page and crawl same-origin links/forms (bounded)."""
    pages: list[str] = []
    endpoints: list[Endpoint] = []
    seen_pages: set[str] = set()
    queue = ["/"]

    while queue and len(pages) < max_pages:
        path = queue.pop(0)
        if path in seen_pages:
            continue
        seen_pages.add(path)
        resp = client.request("GET", path, allow_redirects=True)
        if not resp.ok:
            continue
        pages.append(path)
        parser = _LinkFormParser()
        try:
            parser.feed(resp.text or "")
        except Exception:  # noqa: BLE001 - malformed HTML must not kill the agent
            pass

        for href in parser.links:
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            full = client.absolute(href)
            if not client.same_origin(full):
                continue
            clean = re.sub(r"https?://[^/]+", "", full) or "/"
            if _SKIP_EXT.search(clean):
                continue
            if clean not in seen_pages:
                queue.append(clean)

        for form in parser.forms:
            action = form["action"] or path
            names = form["inputs"][:max_params]
            endpoints.append(Endpoint(
                url=client.absolute(action),
                method=form["method"],
                params={n: "test" for n in names},
                kind="form",
                source=f"form@{path}",
            ))

        # query parameters already present in links
        for href in parser.links:
            if "?" not in href:
                continue
            path_part, _, query = href.partition("?")
            names = [kv.split("=")[0] for kv in query.split("&") if kv]
            if names:
                endpoints.append(Endpoint(
                    url=client.absolute(path_part),
                    method="GET",
                    params={n: "test" for n in names[:max_params]},
                    kind="query",
                    source=f"link@{path}",
                ))
    return pages, endpoints
