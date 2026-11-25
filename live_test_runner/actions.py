"""Extract navigable actions (links and forms) from HTML."""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse


PROBE_VALUES = {
    "text": "probe",
    "search": "probe",
    "email": "probe@example.com",
    "password": "Password1!",
    "number": "1",
    "url": "http://example.com",
    "tel": "1234567890",
}


@dataclass(frozen=True)
class Action:
    method: str
    path: str
    fields: tuple[tuple[str, str], ...] = ()
    label: str = ""

    def describe(self) -> str:
        args = ", ".join(f"{k}={v}" for k, v in self.fields)
        suffix = f" {args}" if args else ""
        return f"{self.label} [{self.method} {self.path}{suffix}]"


def _usable_path(href: str) -> bool:
    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return False
    parsed = urlparse(href)
    # Keep relative and same-document paths; drop absolute external hosts.
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return False
    return True


class ActionParser(HTMLParser):
    """Parse links and forms, including text inputs with probe values."""

    def __init__(self) -> None:
        super().__init__()
        self.actions: list[Action] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs_list) -> None:
        attrs = dict(attrs_list)
        if tag == "a" and "href" in attrs and _usable_path(attrs["href"]):
            href = attrs["href"]
            label = attrs.get("aria-label") or attrs.get("title") or href
            self.actions.append(Action("GET", href, label=label))
        elif tag == "form":
            self._form = {
                "attrs": attrs,
                "fields": [],
                "submits": 0,
            }
        elif self._form is not None and tag == "input":
            itype = (attrs.get("type") or "text").lower()
            name = attrs.get("name")
            if itype == "submit":
                self._form["submits"] += 1
                return
            if itype in ("button", "image", "file", "reset"):
                return
            if not name:
                return
            if itype == "hidden":
                self._form["fields"].append((name, attrs.get("value", "")))
            elif itype == "checkbox":
                self._form["fields"].append((name, attrs.get("value", "on")))
            elif itype == "radio":
                # Keep first radio option only.
                if not any(k == name for k, _ in self._form["fields"]):
                    self._form["fields"].append((name, attrs.get("value", "on")))
            else:
                value = attrs.get("value") or PROBE_VALUES.get(itype, "probe")
                self._form["fields"].append((name, value))
        elif self._form is not None and tag == "textarea":
            name = attrs.get("name")
            if name:
                self._form["fields"].append((name, "probe"))
        elif self._form is not None and tag == "button":
            btype = (attrs.get("type") or "submit").lower()
            if btype == "submit":
                self._form["submits"] += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            attrs = self._form["attrs"]
            fields = tuple(self._form["fields"])
            # Forms without an explicit submit still usually submit somehow;
            # keep them if they have at least one field (e.g. CSRF + inputs).
            if self._form["submits"] or fields:
                method = str(attrs.get("method", "get")).upper()
                if method not in ("GET", "POST"):
                    method = "GET"
                # Empty/missing action means "submit to current page".
                action_path = attrs.get("action")
                if action_path is None or action_path == "":
                    action_path = ""
                if action_path == "" or _usable_path(action_path):
                    label = attrs.get("aria-label") or attrs.get("id") or (action_path or "form")
                    self.actions.append(Action(method, action_path, fields, label))
            self._form = None


def actions_in(html: str, *, current_path: str = "/", limit: int = 40) -> tuple[Action, ...]:
    parser = ActionParser()
    parser.feed(html)
    parser.close()
    current = current_path.split("?", 1)[0] or "/"
    # Deduplicate identical actions while preserving order.
    seen = set()
    unique: list[Action] = []
    for action in parser.actions:
        path = action.path if action.path else current
        resolved = Action(action.method, path, action.fields, action.label or path)
        key = (resolved.method, resolved.path, resolved.fields)
        if key in seen:
            continue
        seen.add(key)
        unique.append(resolved)
        if len(unique) >= limit:
            break
    return tuple(unique)


def resolve_path(base_url: str, path: str) -> str:
    """Join relative action paths against the target base URL."""
    joined = urljoin(base_url.rstrip("/") + "/", path)
    parsed = urlparse(joined)
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")
