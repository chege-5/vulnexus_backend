from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.config import settings
from app.routes import auth_routes
from app.services import oauth_transactions
from app.services.oauth import build_google_auth_url


class FakeRedis:
    values: dict[str, str] = {}

    async def set(self, key, value, ex, nx):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    async def getdel(self, key):
        return self.values.pop(key, None)

    async def aclose(self):
        return None


def test_oauth_transaction_is_opaque_provider_bound_and_single_use(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedis()
    monkeypatch.setattr(oauth_transactions.redis_asyncio.Redis, "from_url", lambda *args, **kwargs: fake)
    monkeypatch.setattr(settings, "OAUTH_STATE_SECRET", "a" * 64)

    async def exercise():
        state, verifier = await oauth_transactions.create_oauth_transaction("google", "signup")
        assert ":" not in state
        payload = await oauth_transactions.consume_oauth_transaction("google", state)
        assert payload["flow"] == "signup"
        assert payload["pkce_verifier"] == verifier
        with pytest.raises(HTTPException, match="already used"):
            await oauth_transactions.consume_oauth_transaction("google", state)

    asyncio.run(exercise())


def test_google_authorization_url_uses_backend_callback_and_pkce(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "google-client")
    callback_uri = "https://api.example.com/api/v1/auth/google/callback"
    monkeypatch.setattr(settings, "GOOGLE_REDIRECT_URI", callback_uri)
    url = build_google_auth_url("opaque-state", callback_uri, "challenge")
    query = parse_qs(urlparse(url).query)
    assert query["redirect_uri"] == [callback_uri]
    assert query["code_challenge"] == ["challenge"]
    assert query["code_challenge_method"] == ["S256"]


def _request() -> Request:
    return Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""})


def test_oauth_start_routes_pass_provider_specific_backend_callbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    google_callback = "https://api.example.com/api/v1/auth/google/callback"
    github_callback = "https://api.example.com/api/v1/auth/github/callback"
    monkeypatch.setattr(settings, "FRONTEND_URL", "https://vulnexus.vercel.app")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "google-client")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "google-secret")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "github-client")
    monkeypatch.setattr(settings, "GITHUB_CLIENT_SECRET", "github-secret")
    monkeypatch.setattr(settings, "GOOGLE_REDIRECT_URI", google_callback)
    monkeypatch.setattr(settings, "GITHUB_REDIRECT_URI", github_callback)

    async def fake_transaction(provider: str, flow: str, *, link_user_id=None):
        assert flow == "login"
        assert link_user_id is None
        return f"{provider}-opaque-state", "pkce-verifier"

    monkeypatch.setattr(auth_routes, "create_oauth_transaction", fake_transaction)

    async def exercise():
        google_response = await auth_routes._oauth_login_redirect("google", _request(), None, "login")
        github_response = await auth_routes._oauth_login_redirect("github", _request(), None, "login")
        return google_response.headers["location"], github_response.headers["location"]

    google_location, github_location = asyncio.run(exercise())
    assert parse_qs(urlparse(google_location).query)["redirect_uri"] == [google_callback]
    assert parse_qs(urlparse(github_location).query)["redirect_uri"] == [github_callback]
    assert "vulnexus.vercel.app" not in google_location
    assert "vulnexus.vercel.app" not in github_location


def test_oauth_callback_routes_are_registered_at_provider_callback_paths() -> None:
    route_paths = {route.path for route in auth_routes.router.routes}
    assert "/google/callback" in route_paths
    assert "/github/callback" in route_paths
