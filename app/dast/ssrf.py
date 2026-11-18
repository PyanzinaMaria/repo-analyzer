from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from app.dast.config import DastConfig


class DastTargetError(ValueError):
    """Raised when a DAST target URL is rejected by policy."""


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool) -> str | None:
    if ip.is_loopback and not allow_private:
        return "loopback addresses are blocked"
    if ip.is_link_local:
        return "link-local addresses are blocked"
    if ip.is_multicast:
        return "multicast addresses are blocked"
    if ip.is_unspecified:
        return "unspecified addresses are blocked"
    # Cloud metadata / common SSRF sink
    if ip == ipaddress.ip_address("169.254.169.254"):
        return "cloud metadata endpoint is blocked"
    if (not allow_private) and (ip.is_private or ip.is_reserved):
        return "private/reserved addresses are blocked"
    return None


def validate_target_url(url: str, cfg: DastConfig) -> str:
    """Validate scheme/host and resolve DNS to enforce SSRF policy.

    Returns the normalized URL string on success.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in cfg.allowed_schemes:
        raise DastTargetError(f"scheme {scheme!r} is not allowed")
    host = parsed.hostname
    if not host:
        raise DastTargetError("target URL has no hostname")

    # Literal IP in URL
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        reason = _is_blocked_ip(literal, allow_private=cfg.allow_private_targets)
        if reason:
            raise DastTargetError(f"target host blocked: {reason}")
        return url

    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if scheme == "https" else 80))
    except socket.gaierror as exc:
        raise DastTargetError(f"cannot resolve host {host!r}: {exc}") from exc

    if not infos:
        raise DastTargetError(f"cannot resolve host {host!r}")

    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        reason = _is_blocked_ip(ip, allow_private=cfg.allow_private_targets)
        if reason:
            raise DastTargetError(f"resolved address {ip} blocked: {reason}")

    return url
