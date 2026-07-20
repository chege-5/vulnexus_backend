"""Durable, single-use OAuth authorization transactions.

OAuth state is deliberately opaque.  The browser only carries the random state
value while Redis holds provider, flow, PKCE verifier and (for account linking)
the authenticated user id.  `GETDEL` makes a successful callback one-time use.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Any

from fastapi import HTTPException, status
from redis import asyncio as redis_asyncio

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


def new_state() -> str:
    return secrets.token_urlsafe(32)


def new_pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def pkce_challenge(verifier: str) -> str:
    import base64
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _key(provider: str, state: str) -> str:
    return f"oauth:{provider}:{state}"


def _state_fingerprint(state: str) -> str:
    return hmac.new(settings.OAUTH_STATE_SECRET.encode("utf-8"), state.encode("utf-8"), hashlib.sha256).hexdigest()


async def create_oauth_transaction(provider: str, flow: str, *, link_user_id: str | None = None) -> tuple[str, str]:
    state = new_state()
    verifier = new_pkce_verifier()
    payload = {
        "provider": provider,
        "flow": flow,
        "pkce_verifier": verifier,
        "state_fingerprint": _state_fingerprint(state),
        "nonce": secrets.token_urlsafe(24),
        "issued_at": int(time.time()),
        "link_user_id": link_user_id,
    }
    client = redis_asyncio.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        created = await client.set(_key(provider, state), json.dumps(payload), ex=settings.OAUTH_STATE_TTL_SECONDS, nx=True)
        if not created:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="OAuth sign-in is temporarily unavailable")
    except Exception as exc:
        logger.error("OAuth transaction store unavailable: provider=%s error_type=%s", provider, type(exc).__name__)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="OAuth sign-in is temporarily unavailable") from exc
    finally:
        await client.aclose()
    return state, verifier


async def consume_oauth_transaction(provider: str, state: str | None) -> dict[str, Any]:
    if not state or len(state) < 32:
        raise HTTPException(status_code=400, detail="OAuth state is missing or invalid")
    client = redis_asyncio.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        raw = await client.getdel(_key(provider, state))
    except Exception as exc:
        logger.error("OAuth transaction consume unavailable: provider=%s error_type=%s", provider, type(exc).__name__)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="OAuth sign-in is temporarily unavailable") from exc
    finally:
        await client.aclose()
    if not raw:
        raise HTTPException(status_code=400, detail="OAuth state has expired or was already used")
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="OAuth state is invalid") from exc
    if payload.get("provider") != provider or not hmac.compare_digest(payload.get("state_fingerprint", ""), _state_fingerprint(state)):
        raise HTTPException(status_code=400, detail="OAuth state provider mismatch")
    return payload
