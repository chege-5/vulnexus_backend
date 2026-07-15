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
