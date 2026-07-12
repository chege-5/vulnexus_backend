from __future__ import annotations

import pytest

import importlib
from app.services.intelligence.llm_engine import InMemoryRateLimiter, LLMRateLimitExceeded, OpenAICompatibleProvider


llm_engine_module = importlib.import_module("app.services.intelligence.llm_engine")


class DummyResponse:
    status_code = 200

    def __init__(self, payload: dict):
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self.payload


class DummyClient:
    requests: list[dict] = []

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def post(self, url, *, json, headers):
        self.requests.append({"url": url, "json": json, "headers": headers})
        return DummyResponse({"choices": [{"message": {"content": "Grounded model explanation."}}]})


def test_openai_provider_calls_chat_completions(monkeypatch):
    DummyClient.requests = []
    monkeypatch.setattr(llm_engine_module.httpx, "Client", DummyClient)

    provider = OpenAICompatibleProvider(
        api_key="test-key",
        base_url="https://provider.example/v1",
        model="provider/model",
        rate_limiter=InMemoryRateLimiter("10/minute"),
    )

    result = provider.generate(
        prompt="Explain the finding.",
        context={"title": "Weak TLS", "risk": {"severity": "High"}},
    )

    assert result == "Grounded model explanation."
    request = DummyClient.requests[0]
    assert request["url"] == "https://provider.example/v1/chat/completions"
    assert request["headers"]["Authorization"] == "Bearer test-key"
    assert request["json"]["model"] == "provider/model"
    assert request["json"]["messages"][1]["content"].startswith("Explain the finding.")


def test_openai_provider_accepts_full_chat_completions_url():
    provider = OpenAICompatibleProvider(
        api_key="test-key",
        base_url="https://provider.example/v1/chat/completions",
        model="provider/model",
    )

    assert provider._chat_completions_url(provider.base_url) == "https://provider.example/v1/chat/completions"


def test_openai_provider_falls_back_without_key():
    provider = OpenAICompatibleProvider(api_key="", base_url="https://provider.example/v1", model="provider/model")

    result = provider.generate(
        prompt="Explain the finding.",
        context={"title": "Weak TLS", "risk": {"severity": "High", "score": 80}, "evidence": [], "recommendations": ["Upgrade TLS"]},
    )

    assert "Weak TLS" in result
    assert "Recommended actions" in result


def test_llm_rate_limiter_blocks_after_limit():
    limiter = InMemoryRateLimiter("1/minute")

    limiter.acquire()
    with pytest.raises(LLMRateLimitExceeded):
        limiter.acquire()
