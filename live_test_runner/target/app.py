"""HTTP booklet stand — same state machine as offline html_fixture, over the network.

Intentionally weak security posture so quality detectors have something to count.
"""

from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass, replace
from html import escape
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


PROOFS = ("text-proof", "screen-proof", "print-proof")
COOKIE_NAME = "booklet"
HOST = "0.0.0.0"
PORT = 8080


@dataclass(frozen=True)
class Booklet:
    page: str = "/"
    text: str = "empty"
    palette: str = "plain"
    cover: bool = False


def render(book: Booklet, *, query: dict[str, list[str]] | None = None) -> str:
    def link(path: str, label: str) -> str:
        return f'<a href="{path}" aria-label="{label}">{label}</a>'

    def form(field: str, value: str, label: str) -> str:
        return (
            f'<form method="post" action="{book.page}" aria-label="{label}">'
            f'<input type="hidden" name="{field}" value="{value}">'
            f'<button type="submit">{label}</button></form>'
        )

    home = link("/", "Home")
    body: list[str] = []
    match book.page:
        case "/":
            body = [
                link("/text", "Text"),
                link("/palette", "Palette"),
                link("/cover", "Cover"),
                link("/preview", "Preview"),
                link("/echo?q=sandbox", "Echo probe"),
            ]
        case "/text":
            body = [
                form("text", value, f"Set text: {value}")
                for value in ("empty", "draft", "final")
            ] + [home]
        case "/palette":
            body = [
                form("palette", value, f"Set palette: {value}")
                for value in ("plain", "blue", "green")
            ] + [home]
        case "/cover":
            body = [
                form(
                    "cover",
                    "off" if book.cover else "on",
                    "Remove cover" if book.cover else "Add cover",
                ),
                home,
            ]
        case "/preview":
            body = [home]
            if book.text == "draft" and book.palette == "green" and not book.cover:
                body += [link("/text-proof", "Open text proof")]
            if book.text == "final" and book.cover:
                if book.palette == "blue":
                    body += [link("/screen-proof", "Open screen proof")]
                if book.palette == "green":
                    body += [link("/print-proof", "Open print proof")]
        case "/echo":
            reflected = (query or {}).get("q", [""])[0]
            body = [
                f"<p>Echo: {reflected}</p>",  # deliberate reflection, unescaped
                home,
            ]
        case "/boom":
            raise RuntimeError("intentional server error")
        case _:
            body = ["<p>Preview generated.</p>"]

    status = (
        f"text={book.text}; palette={book.palette}; "
        f"cover={'on' if book.cover else 'off'}"
    )
    return (
        f"<html><body><h1>{escape(book.page)}</h1><p>{status}</p>"
        f"{''.join(body)}</body></html>"
    )


def load_booklet(cookie_header: str | None) -> Booklet:
    if not cookie_header:
        return Booklet()
    jar = SimpleCookie()
    try:
        jar.load(cookie_header)
    except Exception:
        return Booklet()
    if COOKIE_NAME not in jar:
        return Booklet()
    try:
        raw = base64.urlsafe_b64decode(jar[COOKIE_NAME].value.encode("ascii"))
        data = json.loads(raw.decode("utf-8"))
        return Booklet(
            page=str(data.get("page", "/")),
            text=str(data.get("text", "empty")),
            palette=str(data.get("palette", "plain")),
            cover=bool(data.get("cover", False)),
        )
    except (TypeError, ValueError, json.JSONDecodeError, OSError):
        return Booklet()


def apply_get(book: Booklet, path: str) -> Booklet:
    return replace(book, page=path or "/")


def apply_post(book: Booklet, fields: dict[str, list[str]]) -> Booklet:
    updates: dict = {}
    if "text" in fields:
        updates["text"] = fields["text"][0]
    if "palette" in fields:
        updates["palette"] = fields["palette"][0]
    if "cover" in fields:
        updates["cover"] = fields["cover"][0] == "on"
    return replace(book, **updates) if updates else book


class Handler(BaseHTTPRequestHandler):
    server_version = "BookletHTTP/1.0"

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        print(f"[webapp] {self.address_string()} {format % args}", flush=True)

    def _read_booklet(self) -> Booklet:
        return load_booklet(self.headers.get("Cookie"))

    def _set_booklet_cookie(self, book: Booklet) -> None:
        payload = base64.urlsafe_b64encode(
            json.dumps(asdict(book), separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        # Intentionally missing Secure / HttpOnly / SameSite.
        self.send_header(
            "Set-Cookie",
            f"{COOKIE_NAME}={payload}; Path=/",
        )

    def _weak_headers(self) -> None:
        self.send_header("Server", "BookletHTTP/1.0")
        self.send_header("X-Powered-By", "live-test-runner")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        # Deliberately omit: Content-Security-Policy, X-Frame-Options,
        # X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy.

    def _send_html(self, book: Booklet, html: str, status: int = 200) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._weak_headers()
        self._set_booklet_cookie(book)
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, status: int = 200) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._weak_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        query = parse_qs(parsed.query)

        if path == "/health":
            self._send_text("ok")
            return
        if path == "/_reset":
            book = Booklet()
            self._send_html(book, render(book))
            return
        if path == "/boom":
            self._send_text("boom", status=500)
            return
        if path == "/missing":
            self._send_text("not found", status=404)
            return

        book = apply_get(self._read_booklet(), path)
        try:
            html = render(book, query=query)
        except RuntimeError:
            self._send_text("error", status=500)
            return
        self._send_html(book, html)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        fields = parse_qs(raw, keep_blank_values=True)
        book = apply_post(apply_get(self._read_booklet(), path), fields)
        self._send_html(book, render(book))


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Booklet webapp listening on http://{HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
