"""Repo URL validator.

Strict allowlist of git hosting providers; rejects SSRF-flavoured URLs.
Returns a sanitized https URL or raises ValueError.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}


class InvalidRepoURL(ValueError):
    pass


def validate_repo_url(url: str) -> str:
    if not url or len(url) > 2048:
        raise InvalidRepoURL("URL missing or too long")

    parsed = urlparse(url.strip())

    if parsed.scheme.lower() != "https":
        raise InvalidRepoURL("Only https URLs are accepted")

    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise InvalidRepoURL("Credentials in URL are not allowed")

    host = (parsed.hostname or "").lower()
    if not host:
        raise InvalidRepoURL("Missing host")

    if host not in ALLOWED_HOSTS:
        raise InvalidRepoURL(f"Host '{host}' is not on the allowlist")

    if parsed.port and parsed.port not in (None, 443):
        raise InvalidRepoURL("Non-standard ports are not allowed")

    # Defence-in-depth: refuse if hostname resolves to a private/link-local/loopback IP.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise InvalidRepoURL(f"Host did not resolve: {host}") from e

    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise InvalidRepoURL("Host resolves to a non-public address")

    path = parsed.path.rstrip("/")
    if not path or path.count("/") < 2:
        raise InvalidRepoURL("URL must point to a repository (org/repo)")

    return f"https://{host}{path}"
