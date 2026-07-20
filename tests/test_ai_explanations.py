import pytest

from app.services.ai.explanations import AIExplanationService


@pytest.mark.asyncio
async def test_ai_explanation_falls_back_to_structured_deterministic_remediation(monkeypatch):
    service = AIExplanationService()
    monkeypatch.setattr("app.services.ai.explanations.settings.ENABLE_AI_ENRICHMENT", False)

    result = await service.explain_scan(
        target="https://example.com",
        score=72,
        findings=[{
            "rule_id": "WEAK_TLS_VERSION",
            "description": "TLS 1.0 is enabled.",
            "severity": "High",
            "remediation": "Disable TLS 1.0 and require TLS 1.2 or newer.",
        }],
    )

    assert result["provider"] == "deterministic"
    assert result["assisted"] is False
    assert "WEAK_TLS_VERSION" in result["summary"]
    assert result["remediation_steps"]
    assert result["verification_steps"]


@pytest.mark.asyncio
async def test_empty_scan_never_calls_an_ai_provider(monkeypatch):
    service = AIExplanationService()

    async def provider_call(*_args, **_kwargs):
        raise AssertionError("AI provider must not be called for an empty scan")

    monkeypatch.setattr(service, "_request", provider_call)
    result = await service.explain_scan(target="https://example.com", score=0, findings=[])

    assert result == {
        "status": "not_required",
        "provider": None,
        "assisted": False,
        "summary": "No findings were available for AI review.",
        "findings_reviewed": 0,
        "provider_attempts": [],
    }


@pytest.mark.asyncio
async def test_provider_failure_is_explicitly_marked_as_deterministic_fallback(monkeypatch):
    service = AIExplanationService()
    monkeypatch.setattr("app.services.ai.explanations.settings.ENABLE_AI_ENRICHMENT", True)
    monkeypatch.setattr("app.services.ai.explanations.settings.NVIDIA_API_KEY", "test-key")
    monkeypatch.setattr("app.services.ai.explanations.settings.OPENROUTER_API_KEY", None)

    async def provider_call(*_args, **_kwargs):
        raise RuntimeError("unavailable")

    monkeypatch.setattr(service, "_request", provider_call)
    result = await service.explain_scan(
        target="https://example.com",
        score=72,
        findings=[{"rule_id": "WEAK_TLS_VERSION", "description": "TLS 1.0 is enabled.", "severity": "High"}],
    )

    assert result["status"] == "completed_fallback"
    assert result["provider"] == "deterministic"
    assert result["assisted"] is False
    assert result["provider_attempts"][0]["provider"] == "nvidia"
    assert result["provider_attempts"][0]["status"] == "failed"
