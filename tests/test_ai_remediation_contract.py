import json

import pytest

from app.config import settings
from app.services.ai.explanations import AIExplanationService, AIExplanationUnavailable, ProviderConfig


def test_remediation_payload_is_bounded_and_redacts_private_ips_and_secrets():
    payload = AIExplanationService().payload_builder.build(
        scan_id="scan", scan_type="file", target="https://user:secret@example.com",
        findings=[{"id": "finding", "rule_id": "RULE", "severity": "High", "file_path": "src/settings.py", "line_number": 4, "evidence": {"token": "super-secret", "host": "10.2.3.4"}, "remediation": "Rotate the credential."}],
    )
    serialized = json.dumps(payload)
    assert "super-secret" not in serialized
    assert "10.2.3.4" not in serialized
    assert payload["findings"][0]["finding_id"] == "finding"


@pytest.mark.asyncio
async def test_structured_response_rejects_mismatched_finding_ids(monkeypatch):
    service = AIExplanationService()
    monkeypatch.setattr("app.services.ai.explanations.settings.ENABLE_AI_ENRICHMENT", True)
    monkeypatch.setattr("app.services.ai.explanations.settings.NVIDIA_API_KEY", "test")
    monkeypatch.setattr("app.services.ai.explanations.settings.OPENROUTER_API_KEY", None)

    async def response(*_args, **_kwargs):
        return json.dumps({"findings": [{"finding_id": "wrong", "risk_explanation": "The supplied evidence indicates a security concern.", "mitigation_steps": ["Apply a safe correction."], "short_example_scenario": "An attacker could misuse an exposed weak setting.", "safe_guidance": "Use the documented secure configuration.", "validation_steps": ["Rerun the scan."], "limitations": "The result does not prove exploitation."}]})

    monkeypatch.setattr(service, "_request", response)
    payload = service.payload_builder.build(scan_id="s", scan_type="file", target="target", findings=[{"id": "expected", "rule_id": "RULE"}])
    with pytest.raises(AIExplanationUnavailable):
        await service.remediate(payload=payload)


def test_nvidia_request_shape_uses_documented_user_only_contract():
    service = AIExplanationService()
    provider = ProviderConfig(
        name="nvidia",
        base_url="https://integrate.api.nvidia.com/v1",
        api_key="test-key",
        model="nvidia/nemotron-3-nano-30b-a3b",
        timeout_seconds=25,
    )
    payload = service.payload_builder.build(
        scan_id="scan", scan_type="url", target="https://example.com", findings=[{"id": "finding", "rule_id": "TLS"}],
    )

    body = service._request_body(provider, payload)

    assert body["model"] == "nvidia/nemotron-3-nano-30b-a3b"
    assert body["messages"] and body["messages"][0]["role"] == "user"
    assert "response_format" not in body
    assert body["stream"] is False
    assert body["chat_template_kwargs"] == {"enable_thinking": False}
    assert body["temperature"] == 0.1
    assert body["max_tokens"] == settings.AI_REMEDIATION_MAX_TOKENS
    assert "top_p" not in body
    assert '"finding_id":"finding"' in body["messages"][0]["content"]
