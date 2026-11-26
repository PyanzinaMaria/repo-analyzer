"""Tiny deliberately vulnerable web app for testing the pentest agent.

Standard library only (no Flask dependency). Run:

    python tests/fixtures/vuln_web_app.py --port 5001

Endpoints:
  /search?q=...    SQL-инъекция: ошибка sqlite3 попадает в ответ
  /hello?name=...  отражённый XSS без экранирования
  /file?path=...   path traversal: маркер /etc/passwd в ответе
  /redirect?next=  open redirect через Location
  /run?cmd=...     имитация command injection (маркер в ответе)
  /boom            traceback в ответе
"""
from __future__ import annotations

import argparse
import sqlite3
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_MARKER = "PENTEST_CMD_9f3a"
_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnDemo/0.1"

    def log_message(self, fmt, *args):  # keep the test output clean
        pass

    def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8",
              headers: dict[str, str] | None = None) -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        path = parsed.path

        if path == "/":
            self._send(200, """<html><body>
                <a href="/search?q=cron">search</a>
                <a href="/hello?name=guest">hello</a>
                <a href="/file?path=readme.txt">file</a>
                <a href="/redirect?next=/home">redirect</a>
                <a href="/run?cmd=id">run</a>
                <a href="/boom">boom</a>
                <form action="/search" method="get"><input name="q"></form>
            </body></html>""")
        elif path == "/search":
            q = qs.get("q", "")
            try:
                conn = sqlite3.connect(":memory:")
                conn.execute("CREATE TABLE t(x)")
                conn.execute(f"SELECT * FROM t WHERE x = '{q}'").fetchall()
                self._send(200, f"<html><body>results for {q}</body></html>")
            except sqlite3.OperationalError as exc:
                self._send(500, f"<html><body>sqlite3.OperationalError: {exc}</body></html>")
        elif path == "/hello":
            name = qs.get("name", "")
            self._send(200, f"<html><body><h1>Hello, {name}</h1></body></html>")
        elif path == "/file":
            target = qs.get("path", "")
            if "etc/passwd" in target.replace("\\", "/"):
                self._send(200, _PASSWD, "text/plain")
            else:
                self._send(404, "not found", "text/plain")
        elif path == "/redirect":
            nxt = qs.get("next", "/")
            self._send(302, "", headers={"Location": nxt})
        elif path == "/run":
            cmd = qs.get("cmd", "")
            out = _MARKER if "echo" in cmd else "done"
            self._send(200, f"<html><body>{out}</body></html>")
        elif path == "/boom":
            try:
                raise ValueError("boom")
            except ValueError:
                tb = traceback.format_exc()
            self._send(500, f"<html><body><pre>{tb}</pre></body></html>")
        else:
            self._send(404, "not found")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5001)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"vuln demo on http://{args.host}:{args.port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
