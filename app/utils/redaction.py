from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SECRET_KEY_PATTERN = re.compile(
    r"(?ix)"
    r"(api[_-]?key|apikey|access[_-]?key(?:[_-]?id)?|secret|salt|secret[_-]?access[_-]?key|"
    r"client[_-]?secret|oauth[_-]?secret|jwt[_-]?secret|signing[_-]?key|"
    r"encryption[_-]?key|private[_-]?key(?:[_-]?id)?|public[_-]?key[_-]?id|key|"
    r"key[_-]?id|bearer[_-]?token|access[_-]?token|refresh[_-]?token|token|"
    r"password|passwd|pwd|database[_-]?url|connection[_-]?string|auth|"
    r"credential|credentials|certificate[_-]?password|keystore[_-]?password)"
)

FULL_REDACT_KEY_PATTERN = re.compile(
    r"(?ix)(password|passwd|pwd|token|bearer|secret|private[_-]?key|authorization|cookie|session)"
)

ASSIGNMENT_PATTERN = re.compile(
    r"(?ix)"
    r"(?P<prefix>(?:export\s+)?[\"']?(?P<key>[A-Za-z0-9_.-]*(?:api[_-]?key|apikey|access[_-]?key(?:[_-]?id)?|"
    r"secret|salt|secret[_-]?access[_-]?key|client[_-]?secret|oauth[_-]?secret|jwt[_-]?secret|signing[_-]?key|"
    r"encryption[_-]?key|private[_-]?key(?:[_-]?id)?|public[_-]?key[_-]?id|key[_-]?id|key|"
    r"bearer[_-]?token|access[_-]?token|refresh[_-]?token|token|password|passwd|pwd|database[_-]?url|"
    r"connection[_-]?string|auth|credential|credentials|certificate[_-]?password|keystore[_-]?password)[A-Za-z0-9_.-]*)[\"']?"
    r"\s*(?:=>|:|=)\s*[\"']?)"
    r"(?P<value>[^\"'\n\r,}]+)"
)

PRIVATE_KEY_BLOCK_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
BEARER_PATTERN = re.compile(r"(Bearer\s+)([A-Za-z0-9._\-]{12,})", re.IGNORECASE)
AUTH_HEADER_PATTERN = re.compile(r"(Authorization\s*[:=]\s*)([^\n\r]+)", re.IGNORECASE)
COOKIE_PATTERN = re.compile(r"((?:Cookie|Set-Cookie)\s*:\s*)([^\n\r]+)", re.IGNORECASE)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
URL_CREDENTIAL_PATTERN = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://[^:/\s]+:)([^@\s]+)(@)")
SENSITIVE_QUERY_KEYS = {"token", "access_token", "refresh_token", "api_key", "apikey", "key", "secret", "password", "pwd", "auth"}


def redact_text(value: Any) -> str:
    text = "" if value is None else str(value)
    text = PRIVATE_KEY_BLOCK_PATTERN.sub("[PRIVATE KEY REDACTED]", text)
    text = AUTH_HEADER_PATTERN.sub(lambda m: f"{m.group(1)}[REDACTED]", text)
    text = COOKIE_PATTERN.sub(lambda m: f"{m.group(1)}[REDACTED]", text)
    text = BEARER_PATTERN.sub(lambda m: f"{m.group(1)}[REDACTED]", text)
    text = JWT_PATTERN.sub("[JWT REDACTED]", text)
    text = URL_CREDENTIAL_PATTERN.sub(lambda m: f"{m.group(1)}[REDACTED]{m.group(3)}", text)
    text = ASSIGNMENT_PATTERN.sub(_redact_assignment_match, text)
    text = _redact_sensitive_query_params(text)
    text = re.sub(
        r"(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}",
        lambda m: _partial_mask(m.group(0)),
        text,
    )
    return text


def redact_data(value: Any) -> Any:
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if SECRET_KEY_PATTERN.search(str(key)):
                redacted[key] = _mask_value_by_key(str(key), item)
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


def redact_json_string(value: Any) -> str:
    return json.dumps(redact_data(value), default=str)


def _redact_assignment_match(match: re.Match[str]) -> str:
    key = match.group("key")
    value = match.group("value").strip()
    return f"{match.group('prefix')}{_mask_value_by_key(key, value)}"


def _mask_value_by_key(key: str, value: Any) -> str:
    text = "" if value is None else str(value)
    if FULL_REDACT_KEY_PATTERN.search(key):
        return "[REDACTED]"
    if len(text) <= 8:
        return "[REDACTED]"
    return _partial_mask(text)


def _partial_mask(value: str) -> str:
    text = str(value)
    if len(text) <= 8:
        return "[REDACTED]"
    return f"{text[:4]}...{text[-4:]}"


def _redact_sensitive_query_params(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        url = match.group(0)
        try:
            parts = urlsplit(url)
        except ValueError:
            return url
        if not parts.query:
            return url
        query = []
        changed = False
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            if key.lower() in SENSITIVE_QUERY_KEYS:
                query.append((key, "[REDACTED]"))
                changed = True
            else:
                query.append((key, value))
        if not changed:
            return url
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))

    return re.sub(r"https?://[^\s\"'<>]+", repl, text)
