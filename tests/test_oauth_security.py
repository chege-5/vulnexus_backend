from __future__ import annotations

import time

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from urllib.parse import parse_qs, urlparse

from app.auth import hash_token
from app.routes.auth_routes import _allowed_oauth_redirect_uri, _sign_oauth_state, _validate_oauth_state
from app.config import settings
from app.services.oauth import build_google_auth_url


def _request_with_oauth_state(state: str | None) -> Request:
    headers = []
    if state:
        headers.append((b"cookie", f"{settings.OAUTH_STATE_COOKIE_NAME}={hash_token(state)}".encode()))
    return Request({"type": "http", "method": "POST", "path": "/api/v1/auth/google/exchange", "headers": headers})


def test_oauth_state_requires_a_matching_browser_cookie() -> None:
    state = _sign_oauth_state("google", "signup", "nonce", issued_at=int(time.time()))

    assert _validate_oauth_state(state, "google", _request_with_oauth_state(state)) == "signup"

    with pytest.raises(HTTPException, match="browser session"):
        _validate_oauth_state(state, "google", _request_with_oauth_state(None))


def test_oauth_state_rejects_tampering_and_expiry() -> None:
    state = _sign_oauth_state("google", "login", "nonce", issued_at=int(time.time()))
    tampered = f"{state[:-1]}{'0' if state[-1] != '0' else '1'}"

    with pytest.raises(HTTPException, match="signature"):
        _validate_oauth_state(tampered, "google", _request_with_oauth_state(tampered))

    expired = _sign_oauth_state(
        "google",
        "login",
        "nonce",
        issued_at=int(time.time()) - settings.OAUTH_STATE_TTL_SECONDS - 1,
    )
    with pytest.raises(HTTPException, match="expired"):
        _validate_oauth_state(expired, "google", _request_with_oauth_state(expired))


def test_google_production_callback_is_allowed_only_by_deployed_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    callback_uri = "https://vulnexus.vercel.app/auth/google/callback"
    monkeypatch.setattr(settings, "GOOGLE_REDIRECT_URI", callback_uri)
    monkeypatch.setattr(settings, "CORS_ORIGINS", "https://vulnexus.vercel.app")

    assert _allowed_oauth_redirect_uri("google", callback_uri) == callback_uri
    authorization_url = build_google_auth_url("state-value", callback_uri)
    assert parse_qs(urlparse(authorization_url).query)["redirect_uri"] == [callback_uri]
