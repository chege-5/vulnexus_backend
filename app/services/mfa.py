from __future__ import annotations

import base64
import hmac
import secrets
import struct
import time
from hashlib import sha1
from urllib.parse import quote, urlencode

from app.auth import hash_token
from app.config import settings


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def provisioning_uri(*, secret: str, account_name: str) -> str:
    label = f"{settings.MFA_ISSUER}:{account_name}"
    params = urlencode({"secret": secret, "issuer": settings.MFA_ISSUER, "algorithm": "SHA1", "digits": 6, "period": 30})
    return f"otpauth://totp/{quote(label)}?{params}"


def verify_totp(secret: str | None, code: str, *, now: int | None = None, window: int = 1) -> bool:
    if not secret:
        return False
    clean = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(clean) != 6:
        return False
    timestamp = int(now if now is not None else time.time())
    counter = timestamp // 30
    return any(hmac.compare_digest(clean, _totp(secret, counter + offset)) for offset in range(-window, window + 1))


def generate_recovery_codes(count: int = 8) -> tuple[list[str], list[str]]:
    codes = [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(count)]
    return codes, [hash_token(code) for code in codes]


def consume_recovery_code(stored_hashes: list[str] | None, code: str) -> tuple[bool, list[str]]:
    hashes = list(stored_hashes or [])
    candidate = hash_token((code or "").strip())
    for index, value in enumerate(hashes):
        if hmac.compare_digest(candidate, value):
            del hashes[index]
            return True, hashes
    return False, hashes


def _totp(secret: str, counter: int) -> str:
    normalized = secret.upper() + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(normalized, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"
