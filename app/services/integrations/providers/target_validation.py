from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def public_ip_or_none(value: str) -> str | None:
    """Return a public IP only; provider adapters never accept hosts or URLs."""
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None
    if any((ip.is_private, ip.is_loopback, ip.is_link_local, ip.is_multicast, ip.is_reserved, ip.is_unspecified)):
        return None
    return str(ip)


def domain_from_value(value: str) -> str | None:
    raw = (value or "").strip().lower()
    if not raw:
        return None
    parsed = urlsplit(raw)
    host = parsed.hostname if parsed.scheme else raw.split("/", 1)[0]
    if not host or public_ip_or_none(host):
        return None
    labels = host.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host
