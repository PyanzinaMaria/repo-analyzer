from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from app.dast.agent.crawl import Endpoint


@dataclass
class ProbeResult:
    kind: str                 # sqli | xss | path_traversal | open_redirect | cmd_injection | headers | error_disclosure
    title: str
    cwe: str
    severity: str             # critical | high | medium | low | info
    url: str
    payload: str = ""
    evidence: str = ""
    request: str = ""
    response: str = ""
    confidence: str = "medium"  # high | medium | low
    tags: list[str] = field(default_factory=list)


_SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysqli",
    r"pg_query\(\)",
    r"psql:.*syntax",
    r"sqlite3\.OperationalError",
    r'SQLSTATE\[',
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for ODBC",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
]

_TRAVERSAL_MARKERS = ["root:x:0:0", "daemon:x:1:1", "[boot loader]"]

_XSS_PAYLOADS = [
    "<script>alert('PENTEST_XSS')</script>",
    '"><img src=x onerror=alert(1)>',
    "'><svg/onload=alert(1)>",
]

_SQL_PAYLOADS = [
    "'",
    "' OR '1'='1",
]

_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
]

_REDIRECT_PAYLOADS = ["https://evil.example/pentest", "//evil.example/pentest"]

_CMD_MARKER = "PENTEST_CMD_9f3a"
_CMD_PAYLOADS = [f"; echo {_CMD_MARKER}", f"| echo {_CMD_MARKER}"]

_PARAM_HINTS = {
    "redirect": {"next", "url", "uri", "redirect", "return", "returnto", "to", "target", "goto", "continue"},
    "traversal": {"path", "file", "filename", "dir", "folder", "download", "page", "template", "src", "resource"},
    "cmd": {"cmd", "exec", "command", "ping", "host", "system", "query", "run"},
}


def _classes_for(param: str) -> list[str]:
    """Pick probe classes by parameter name (cheap targeting), always incl. sqli/xss."""
    low = param.lower()
    classes = ["sqli", "xss"]
    for kind, names in _PARAM_HINTS.items():
        if low in names or any(n in low for n in names):
            classes.append(kind)
    # a parameter with none of the hints still gets the generic checks
    return classes

_ERROR_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"at [\w.]+\([\w.]+\.java:\d+\)", "Java stack trace"),
    (r"<b>Warning</b>:\s*", "PHP warning"),
    (r"Microsoft \.NET Framework", ".NET exception page"),
    (r"Whitelabel Error Page", "Spring Boot error page"),
]

_SECURITY_HEADERS = {
    "content-security-policy": ("CSP", "medium"),
    "x-content-type-options": ("X-Content-Type-Options", "low"),
    "x-frame-options": ("X-Frame-Options", "low"),
    "strict-transport-security": ("HSTS", "low"),
    "referrer-policy": ("Referrer-Policy", "low"),
}


def _baseline(client, ep: Endpoint) -> tuple[dict, object] | None:
    params = dict(ep.params)
    if ep.method == "POST":
        resp = client.request("POST", ep.url, data=params)
    else:
        resp = client.request("GET", ep.url, params=params)
    if not resp.ok:
        return None
    return params, resp


def probe_endpoint(client, ep: Endpoint, max_params: int = 12) -> list[ProbeResult]:
    """Run the active probe set against one endpoint's parameters."""
    base = _baseline(client, ep)
    if base is None:
        return []
    params, base_resp = base
    results: list[ProbeResult] = []
    names = list(params)[:max_params]

    def send(overrides: dict[str, str], follow: bool = False):
        payload = dict(params)
        payload.update(overrides)
        if ep.method == "POST":
            return client.request("POST", ep.url, data=payload, allow_redirects=follow)
        return client.request("GET", ep.url, params=payload, allow_redirects=follow)

    for name in names:
        classes = _classes_for(name)

        # --- SQL injection
        if "sqli" in classes:
            for payload in _SQL_PAYLOADS:
                resp = send({name: payload})
                body = (resp.text or "").lower()
                hit = next((p for p in _SQL_ERRORS if re.search(p, body, re.I)), None)
                if hit:
                    results.append(ProbeResult(
                        kind="sqli", title="SQL-инъекция (ошибка БД в ответе)",
                        cwe="CWE-089", severity="high", url=resp.url, payload=payload,
                        evidence=f"ответ содержит ошибку SQL: {hit}",
                        request=f"{ep.method} {ep.url} ?{name}={payload}",
                        response=resp.snippet(220), confidence="high",
                    ))
                    break

        # --- XSS
        if "xss" in classes:
            for payload in _XSS_PAYLOADS:
                resp = send({name: payload})
                ctype = resp.headers.get("content-type", "")
                if payload in (resp.text or "") and "html" in ctype.lower():
                    results.append(ProbeResult(
                        kind="xss", title="Отражённый XSS (payload вернулся без экранирования)",
                        cwe="CWE-079", severity="high", url=resp.url, payload=payload,
                        evidence="payload присутствует в HTML-ответе как есть",
                        request=f"{ep.method} {ep.url} ?{name}={payload}",
                        response=resp.snippet(220), confidence="high",
                    ))
                    break

        # --- path traversal
        if "traversal" in classes:
            for payload in _TRAVERSAL_PAYLOADS:
                resp = send({name: payload})
                if any(m in (resp.text or "") for m in _TRAVERSAL_MARKERS):
                    results.append(ProbeResult(
                        kind="path_traversal",
                        title="Path traversal (чтение файла за пределами каталога)",
                        cwe="CWE-022", severity="high", url=resp.url, payload=payload,
                        evidence="ответ содержит содержимое /etc/passwd",
                        request=f"{ep.method} {ep.url} ?{name}={payload}",
                        response=resp.snippet(220), confidence="high",
                    ))
                    break

        # --- open redirect
        if "redirect" in classes:
            for payload in _REDIRECT_PAYLOADS:
                resp = send({name: payload}, follow=False)
                loc = resp.headers.get("location", "")
                if loc and "evil.example" in loc:
                    results.append(ProbeResult(
                        kind="open_redirect", title="Open redirect (редирект на внешний домен)",
                        cwe="CWE-601", severity="medium", url=resp.url, payload=payload,
                        evidence=f"Location: {loc}",
                        request=f"{ep.method} {ep.url} ?{name}={payload}",
                        response=resp.snippet(160), confidence="high",
                    ))
                    break

        # --- command injection (marker in output)
        if "cmd" in classes:
            for payload in _CMD_PAYLOADS:
                resp = send({name: payload})
                body = resp.text or ""
                # the marker must be *executed*, not merely reflected: if the
                # response echoes the payload ("echo" is visible), it is
                # reflection, not RCE.
                if _CMD_MARKER in body and "echo" not in body:
                    results.append(ProbeResult(
                        kind="cmd_injection", title="Инъекция команд (маркер в ответе)",
                        cwe="CWE-078", severity="critical", url=resp.url, payload=payload,
                        evidence=f"ответ содержит маркер {_CMD_MARKER} без самого payload",
                        request=f"{ep.method} {ep.url} ?{name}={payload}",
                        response=resp.snippet(220), confidence="high",
                    ))
                    break
    return results


def probe_headers(client, path: str = "/") -> list[ProbeResult]:
    resp = client.request("GET", path)
    if not resp.ok:
        return []
    out: list[ProbeResult] = []
    missing = [f"{name}" for name in _SECURITY_HEADERS if name not in resp.headers]
    if missing:
        out.append(ProbeResult(
            kind="headers", title="Отсутствуют security-заголовки",
            cwe="CWE-693", severity="low", url=resp.url,
            evidence=", ".join(_SECURITY_HEADERS[h][0] for h in missing),
            request=f"GET {resp.url}", response=str(dict(list(resp.headers.items())[:8])),
            confidence="high",
        ))
    return out


def probe_errors(client, pages: Iterable[str]) -> list[ProbeResult]:
    out: list[ProbeResult] = []
    for path in pages:
        resp = client.request("GET", path)
        if not resp.ok:
            continue
        for pattern, label in _ERROR_PATTERNS:
            if re.search(pattern, resp.text or ""):
                out.append(ProbeResult(
                    kind="error_disclosure", title="Раскрытие деталей ошибки/стека",
                    cwe="CWE-209", severity="low", url=resp.url, payload="",
                    evidence=label, request=f"GET {resp.url}",
                    response=resp.snippet(200), confidence="medium",
                ))
                break
    return out
