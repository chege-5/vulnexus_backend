from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from app.config import settings


class InvalidTargetError(ValueError):
    """A user-supplied URL is not safe or valid for a network scan."""


@dataclass(frozen=True, slots=True)
class NormalizedTarget:
    original: str
    normalized_url: str
    scheme: str
    hostname: str
    registered_domain: str | None
    port: int | None
    path: str
    query: str
    resolved_ips: list[str]
    public_ips: list[str]


async def normalize_target(value: str, *, dns_timeout_seconds: float | None = None) -> NormalizedTarget:
    original = (value or "").strip()
    if not original:
        raise InvalidTargetError("A target URL is required")
    try:
        parsed = urlsplit(original)
    except ValueError as exc:
        raise InvalidTargetError("Target URL is invalid") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise InvalidTargetError("Target must be an absolute http or https URL without credentials")

    hostname = parsed.hostname.rstrip(".").lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise InvalidTargetError("Target URL has an invalid port") from exc
    if _is_blocked_ip(hostname):
        raise InvalidTargetError("Private, loopback, and reserved targets are not allowed")

    timeout = dns_timeout_seconds if dns_timeout_seconds is not None else min(
        settings.DNS_RESOLUTION_TIMEOUT_SECONDS,
        settings.INTELLIGENCE_REQUEST_TIMEOUT_SECONDS,
    )
    resolved_ips = await _resolve(hostname, timeout)
    public_ips = [ip for ip in resolved_ips if _is_public_ip(ip)]
    if resolved_ips and not public_ips:
        raise InvalidTargetError("Target resolves only to private, loopback, or reserved addresses")
    if not resolved_ips:
        raise InvalidTargetError("Target hostname could not be resolved")

    netloc = hostname if port is None else f"{hostname}:{port}"
    path = parsed.path or ""
    normalized_url = urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))
    return NormalizedTarget(
        original=original,
        normalized_url=normalized_url,
        scheme=parsed.scheme.lower(),
        hostname=hostname,
        registered_domain=_registered_domain(hostname),
        port=port,
        path=path,
        query=parsed.query,
        resolved_ips=resolved_ips,
        public_ips=public_ips,
    )


def provider_domain(target: NormalizedTarget) -> str:
    return target.registered_domain or target.hostname


async def _resolve(hostname: str, timeout_seconds: float) -> list[str]:
    if _is_ip(hostname):
        return [hostname]
    try:
        rows = await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, hostname, None), timeout=timeout_seconds)
    except (asyncio.TimeoutError, OSError, socket.gaierror):
        return []
    return list(dict.fromkeys(row[4][0] for row in rows))


def _registered_domain(hostname: str) -> str | None:
    if _is_ip(hostname) or hostname == "localhost":
        return None
    labels = hostname.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_blocked_ip(value: str) -> bool:
    return _is_ip(value) and not _is_public_ip(value)


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not any((ip.is_private, ip.is_loopback, ip.is_link_local, ip.is_multicast, ip.is_reserved, ip.is_unspecified))
