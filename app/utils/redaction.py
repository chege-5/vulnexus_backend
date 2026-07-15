from __future__ import annotations

import json
import re
from collections.abc import Mapping
from copy import deepcopy
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


REDACTED = "[REDACTED]"

# These sets intentionally use lower-case values.  Header and query-string
# names are case insensitive, while the original spelling is retained in logs.
SENSITIVE_QUERY_KEYS = {
    "key",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "auth",
    "authorization",
    "password",
    "secret",
    "client_secret",
    "code",
    "signature",
    "sig",
    "x-amz-signature",
    "x-amz-credential",
}
SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "cookie",
    "set-cookie",
    "x-github-token",
}

SENSITIVE_KEY_PATTERN = re.compile(
    r"(?ix)(?:"
    r"api[_-]?key|apikey|access[_-]?key(?:[_-]?id)?|"
    r"secret|salt|client[_-]?secret|oauth[_-]?secret|jwt[_-]?secret|"
    r"signing[_-]?key|encryption[_-]?key|private[_-]?key(?:[_-]?id)?|"
    r"public[_-]?key[_-]?id|key[_-]?id|bearer[_-]?token|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|token|password|passwd|pwd|pass|"
    r"database[_-]?url|connection[_-]?string|auth|credential|credentials|"
    r"certificate[_-]?password|keystore[_-]?password|pat|private)"
)
ASSIGNMENT_PATTERN = re.compile(
    r"(?ix)"
    r"(?P<prefix>(?:export\s+)?[\"']?(?P<key>[A-Za-z0-9_.-]*"
    r"(?:api[_-]?key|apikey|access[_-]?key(?:[_-]?id)?|secret|salt|"
    r"client[_-]?secret|oauth[_-]?secret|jwt[_-]?secret|signing[_-]?key|"
    r"encryption[_-]?key|private[_-]?key(?:[_-]?id)?|public[_-]?key[_-]?id|"
    r"key[_-]?id|key|bearer[_-]?token|access[_-]?token|refresh[_-]?token|"
    r"id[_-]?token|token|password|passwd|pwd|pass|database[_-]?url|"
    r"connection[_-]?string|auth|credential|credentials|pat|private)"
    r"[A-Za-z0-9_.-]*)[\"']?\s*(?:=>|:|=)\s*[\"']?)"
    r"(?P<value>[^\"'\n\r,}\s]+)"
)
PRIVATE_KEY_BLOCK_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
BEARER_PATTERN = re.compile(r'''(Bearer\s+)(?!\[REDACTED\])([^\s,}\]]+)''', re.IGNORECASE)
HEADER_VALUE_PATTERN = re.compile(
    r"(?ix)(?P<prefix>\b(?:Authorization|Proxy-Authorization|X-Api-Key|Api-Key|"
    r"X-Auth-Token|Cookie|Set-Cookie|X-GitHub-Token)\s*[:=]\s*)"
    r"(?P<value>[^\n\r,}]+)"
)
URL_CREDENTIAL_PATTERN = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://[^:/\s]+:)([^@\s]+)(@)")
URL_PATTERN = re.compile(r"(?P<url>[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+)")


def redact_secret(value: Any) -> str:
    """Return a stable safe marker without ever deriving output from a secret."""
    return REDACTED if value is not None else ""


def redact_url(url: Any) -> str:
    """Mask credentials and sensitive query values while preserving useful URL context."""
    if url is None:
        return ""
    text = str(url)
    try:
        parts = urlsplit(text)
    except (TypeError, ValueError):
        return text

    if not parts.scheme or not parts.netloc:
        return text

    try:
        hostname = parts.hostname or ""
        netloc = hostname
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
        if parts.username:
            # A username is not normally a credential, but omitting it avoids
            # accidentally exposing an email address in URLs used for auth flows.
            netloc = f"{REDACTED}@{netloc}"

        query = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            query.append((key, REDACTED if key.casefold() in SENSITIVE_QUERY_KEYS else value))
        safe_query = urlencode(query, doseq=True, safe="[]")
        return urlunsplit((parts.scheme, netloc, parts.path, safe_query, parts.fragment))
    except Exception:
        return REDACTED


def redact_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    """Return a safe copy of headers suitable for diagnostics or reports."""
    if not headers:
        return {}
    safe: dict[str, str] = {}
    for key, value in headers.items():
        key_text = str(key)
        value_text = "" if value is None else str(value)
        if _is_sensitive_key(key_text) or key_text.casefold() in SENSITIVE_HEADER_KEYS:
            if key_text.casefold() in {"authorization", "proxy-authorization"} and value_text.lower().startswith("bearer "):
                safe[key_text] = f"Bearer {REDACTED}"
            else:
                safe[key_text] = REDACTED
        else:
            safe[key_text] = redact_text(value_text)
    return safe


def redact_text(value: Any) -> str:
    """Best-effort redaction for untrusted text.  This must never raise in logging paths."""
    try:
        text = "" if value is None else str(value)
        text = PRIVATE_KEY_BLOCK_PATTERN.sub("[PRIVATE KEY REDACTED]", text)
        text = URL_PATTERN.sub(lambda match: redact_url(match.group("url").rstrip(".,;:)")) + match.group("url")[len(match.group("url").rstrip(".,;:)")):], text)
        text = URL_CREDENTIAL_PATTERN.sub(lambda match: f"{match.group(1)}{REDACTED}{match.group(3)}", text)
        text = ASSIGNMENT_PATTERN.sub(_redact_assignment_match, text)
        text = HEADER_VALUE_PATTERN.sub(lambda match: f"{match.group('prefix')}{_redacted_header_value(match.group('prefix'))}", text)
        text = BEARER_PATTERN.sub(lambda match: f"{match.group(1)}{REDACTED}", text)
        text = JWT_PATTERN.sub("[JWT REDACTED]", text)
        text = re.sub(
            r"(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}",
            REDACTED,
            text,
        )
        return text
    except Exception:
        return REDACTED


def redact_data(value: Any) -> Any:
    """Recursively redact payloads before they reach logs, reports, or exports."""
    try:
        if isinstance(value, Mapping):
            redacted: dict[Any, Any] = {}
            for key, item in value.items():
                key_text = str(key)
                if _is_sensitive_key(key_text) or key_text.casefold() in SENSITIVE_HEADER_KEYS:
                    if key_text.casefold() in {"database_url", "async_database_url", "redis_url", "celery_broker_url", "celery_result_backend"}:
                        redacted[key] = redact_url(item)
                    else:
                        redacted[key] = redact_secret(item)
                elif key_text.casefold() in {"url", "uri", "endpoint", "redirect_uri"}:
                    redacted[key] = redact_url(item)
                elif key_text.casefold() == "headers" and isinstance(item, Mapping):
                    redacted[key] = redact_headers(item)
                else:
                    redacted[key] = redact_data(item)
            return redacted
        if isinstance(value, list):
            return [redact_data(item) for item in value]
        if isinstance(value, tuple):
            return tuple(redact_data(item) for item in value)
        if isinstance(value, str):
            return redact_text(value)
        return deepcopy(value)
    except Exception:
        return REDACTED


def redact_dict(data: Mapping[str, Any] | None) -> dict[str, Any]:
    """Compatibility-friendly named entry point for callers with dictionaries."""
    result = redact_data(data or {})
    return dict(result) if isinstance(result, Mapping) else {}


def redact_log_message(message: Any) -> str:
    return redact_text(message)


def redact_json_string(value: Any) -> str:
    return json.dumps(redact_data(value), default=str)


def _redacted_header_value(prefix: str) -> str:
    return f"Bearer {REDACTED}" if "authorization" in prefix.casefold() else REDACTED


def _is_sensitive_key(key: str) -> bool:
    return key.casefold() == "key" or bool(SENSITIVE_KEY_PATTERN.search(key))


def _redact_assignment_match(match: re.Match[str]) -> str:
    key = match.group("key")
    value = match.group("value")
    if key.casefold() in {"database_url", "async_database_url", "redis_url", "celery_broker_url", "celery_result_backend"}:
        safe_value = redact_url(value)
    else:
        safe_value = redact_secret(value)
    return f"{match.group('prefix')}{safe_value}"
