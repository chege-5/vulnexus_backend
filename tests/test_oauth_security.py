from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException

from app.config import settings
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
