import asyncio
import json

import pytest

from app.services.ai.explanations import AIExplanationService, AIExplanationUnavailable, AIProviderError


def _payload(service: AIExplanationService, finding_ids: list[str] = ["finding-1"]):
    return service.payload_builder.build(
        scan_id="scan", scan_type="url", target="https://example.com",
        findings=[{"id": finding_id, "rule_id": "TLS_TEST", "severity": "Medium"} for finding_id in finding_ids],
    )


def _item(finding_id: str) -> dict:
    return {
        "finding_id": finding_id,
        "risk_explanation": "The configuration could permit weaker transport security.",
        "mitigation_steps": ["Require modern transport settings."],
        "short_example_scenario": "A network attacker could target an obsolete configuration.",
        "safe_guidance": "Apply the documented secure baseline before deployment.",
        "validation_steps": ["Rerun the scan after the configuration change."],
        "limitations": "This response does not prove that exploitation occurred.",
    }


@pytest.mark.asyncio
async def test_eight_finding_partial_response_forwards_only_seven_unresolved_ids(monkeypatch):
    service = AIExplanationService()
    finding_ids = [f"finding-{index}" for index in range(8)]
    fallback_batches = []
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_PRIMARY_PROVIDER", "nvidia")
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_FALLBACK_PROVIDER", "openrouter")
    monkeypatch.setattr("app.services.ai.explanations.settings.NVIDIA_API_KEY", "nvidia-test")
    monkeypatch.setattr("app.services.ai.explanations.settings.OPENROUTER_API_KEY", "router-test")
    # Exercise the provider's exact unresolved-ID handoff independently of
    # production's hard 1–3 finding request cap.
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_REMEDIATION_BATCH_SIZE", 8)

    async def provider_response(*args, **kwargs):
        provider = kwargs["provider"]
        if provider == "nvidia":
            return json.dumps({"findings": [_item("finding-0")]})
        fallback_batches.append(json.loads(args[4]["messages"][1]["content"])["findings"])
        return "not JSON"

    monkeypatch.setattr(service, "_request", provider_response)
    result = await service.remediate(payload=_payload(service, finding_ids))

    assert [item.finding_id for item in result.findings] == ["finding-0"]
    assert result.unresolved_finding_ids == finding_ids[1:]
    assert [item["finding_id"] for item in fallback_batches[0]] == finding_ids[1:]
    assert result.attempts[0]["result_count"] == 1
    assert result.attempts[1]["schema_failure_category"] == "invalid_json"


@pytest.mark.asyncio
async def test_provider_batch_deadline_cancels_slow_openrouter_request(monkeypatch):
    service = AIExplanationService()
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_PRIMARY_PROVIDER", "openrouter")
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_FALLBACK_PROVIDER", "disabled")
    monkeypatch.setattr("app.services.ai.explanations.settings.OPENROUTER_API_KEY", "test-key")
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_REMEDIATION_BATCH_TIMEOUT_SECONDS", 0.02)

    async def slow_response(*_args, **_kwargs):
        await asyncio.sleep(1)
        return json.dumps({"findings": [_item("finding-1")]})

    monkeypatch.setattr(service, "_request", slow_response)
    with pytest.raises(AIExplanationUnavailable) as failure:
        await service.remediate(payload=_payload(service))

    assert failure.value.category == "timeout"
    assert failure.value.attempts[0]["retryable"] is True


@pytest.mark.asyncio
async def test_fenced_json_is_accepted_but_duplicate_ids_are_rejected(monkeypatch):
    service = AIExplanationService()
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_PRIMARY_PROVIDER", "openrouter")
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_FALLBACK_PROVIDER", "disabled")
    monkeypatch.setattr("app.services.ai.explanations.settings.OPENROUTER_API_KEY", "test-key")

    async def fenced(*_args, **_kwargs):
        return "```json\n" + json.dumps({"findings": [_item("finding-1"), _item("finding-1")]}) + "\n```"

    monkeypatch.setattr(service, "_request", fenced)
    with pytest.raises(AIExplanationUnavailable) as failure:
        await service.remediate(payload=_payload(service))

    # All submitted IDs were present, but duplicate output means the response
    # is not a valid completion and must not be persisted as ready.
    assert "duplicate_finding_id" in failure.value.attempts[0]["schema_failure_category"]


@pytest.mark.asyncio
async def test_nvidia_http_400_is_invalid_request_and_not_retryable(monkeypatch):
    service = AIExplanationService()
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_PRIMARY_PROVIDER", "nvidia")
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_FALLBACK_PROVIDER", "disabled")
    monkeypatch.setattr("app.services.ai.explanations.settings.NVIDIA_API_KEY", "test-key")

    async def rejected(*_args, **_kwargs):
        raise AIProviderError("rejected", category="invalid_request", retryable=False, http_status=400, error_code="invalid_role")

    monkeypatch.setattr(service, "_request", rejected)
    with pytest.raises(AIExplanationUnavailable) as failure:
        await service.remediate(payload=_payload(service))

    assert failure.value.category == "invalid_request"
    attempt = failure.value.attempts[0]
    assert attempt["http_status"] == 400
    assert attempt["retryable"] is False
    assert attempt["response_error_code"] == "invalid_role"


@pytest.mark.asyncio
async def test_openrouter_200_invalid_json_is_invalid_response(monkeypatch):
    service = AIExplanationService()
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_PRIMARY_PROVIDER", "openrouter")
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_FALLBACK_PROVIDER", "disabled")
    monkeypatch.setattr("app.services.ai.explanations.settings.OPENROUTER_API_KEY", "test-key")

    async def malformed(*_args, **_kwargs):
        return "not valid JSON"

    monkeypatch.setattr(service, "_request", malformed)
    with pytest.raises(AIExplanationUnavailable) as failure:
        await service.remediate(payload=_payload(service))

    assert failure.value.category == "invalid_response"
    assert failure.value.attempts[0]["http_status"] == 200
    assert failure.value.attempts[0]["response_validation"] == "invalid"
    assert failure.value.attempts[0]["retryable"] is False


@pytest.mark.asyncio
async def test_valid_openrouter_response_is_retained(monkeypatch):
    service = AIExplanationService()
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_PRIMARY_PROVIDER", "openrouter")
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_FALLBACK_PROVIDER", "disabled")
    monkeypatch.setattr("app.services.ai.explanations.settings.OPENROUTER_API_KEY", "test-key")

    async def valid(*_args, **_kwargs):
        return json.dumps({"findings": [_item("finding-1")]})

    monkeypatch.setattr(service, "_request", valid)
    result = await service.remediate(payload=_payload(service))

    assert result.provider == "openrouter"
    assert [item.finding_id for item in result.findings] == ["finding-1"]
    assert result.unresolved_finding_ids == []
    assert result.attempts[0]["response_validation"] == "valid"


@pytest.mark.asyncio
async def test_partial_response_persists_valid_item_and_fails_over_only_unresolved(monkeypatch):
    service = AIExplanationService()
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_PRIMARY_PROVIDER", "nvidia")
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_FALLBACK_PROVIDER", "openrouter")
    monkeypatch.setattr("app.services.ai.explanations.settings.NVIDIA_API_KEY", "test-key")
    monkeypatch.setattr("app.services.ai.explanations.settings.OPENROUTER_API_KEY", "fallback-key")

    calls: list[str] = []

    async def partial(*args, **kwargs):
        calls.append(kwargs["provider"])
        if kwargs["provider"] == "nvidia":
            return json.dumps({"findings": [_item("finding-1")]})
        payload = json.loads(args[4]["messages"][1]["content"])
        assert [item["finding_id"] for item in payload["findings"]] == ["finding-2"]
        return json.dumps({"findings": [_item("finding-2")]})

    monkeypatch.setattr(service, "_request", partial)
    result = await service.remediate(payload=_payload(service, ["finding-1", "finding-2"]))

    assert [item.finding_id for item in result.findings] == ["finding-1", "finding-2"]
    assert result.unresolved_finding_ids == []
    assert result.attempts[0]["response_validation"] == "partial"
    assert calls == ["nvidia", "openrouter"]


@pytest.mark.asyncio
async def test_provider_attempt_logs_never_contain_api_key(monkeypatch, caplog):
    service = AIExplanationService()
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_PRIMARY_PROVIDER", "nvidia")
    monkeypatch.setattr("app.services.ai.explanations.settings.AI_FALLBACK_PROVIDER", "disabled")
    monkeypatch.setattr("app.services.ai.explanations.settings.NVIDIA_API_KEY", "super-secret-api-key")

    async def timeout(*_args, **_kwargs):
        raise AIProviderError("timeout", category="timeout", retryable=True)

    monkeypatch.setattr(service, "_request", timeout)
    with pytest.raises(AIExplanationUnavailable):
        await service.remediate(payload=_payload(service))

    assert "super-secret-api-key" not in caplog.text
