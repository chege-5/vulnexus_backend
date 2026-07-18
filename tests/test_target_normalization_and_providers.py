import asyncio
import base64

import httpx
import pytest

from app.services.ai.explanations import AIExplanationService
from app.services.integrations.base import ProviderSettings
from app.services.integrations.providers.abuseipdb import AbuseIPDBProvider
from app.services.integrations.providers.builtwith import BuiltWithProvider
from app.services.integrations.providers.censys import CensysProvider
from app.services.integrations.providers.ipinfo import IPInfoProvider
from app.services.integrations.providers.shodan import ShodanProvider
from app.services.integrations.providers.urlscan import UrlScanProvider
from app.services.integrations.providers.virustotal import VirusTotalProvider
from app.services.targets import InvalidTargetError, normalize_target, provider_domain
from app.services.orchestration.scan_orchestrator import ScanOrchestrator
from app.services.models.pipeline import RawFinding


@pytest.mark.asyncio
async def test_target_normalization_preserves_http_url_and_maps_provider_inputs(monkeypatch):
    async def resolved(*_args, **_kwargs):
        return ["104.20.23.154", "127.0.0.1"]

    monkeypatch.setattr("app.services.targets.normalization._resolve", resolved)
    target = await normalize_target("HTTPS://WWW.Example.COM:443/path/?a=1#fragment")
    assert target.normalized_url == "https://www.example.com:443/path/?a=1"
    assert target.hostname == "www.example.com"
    assert target.public_ips == ["104.20.23.154"]
    assert target.original_input == "HTTPS://WWW.Example.COM:443/path/?a=1#fragment"
    assert target.resolved_public_ips == ["104.20.23.154"]
    assert target.final_redirect_url == target.normalized_url
    assert target.as_metadata() == {
        "original_input": "HTTPS://WWW.Example.COM:443/path/?a=1#fragment",
        "normalized_url": "https://www.example.com:443/path/?a=1",
        "hostname": "www.example.com",
        "resolved_public_ips": ["104.20.23.154"],
        "final_redirect_url": "https://www.example.com:443/path/?a=1",
        "scanable_target_type": "url",
        "redirects_followed": False,
    }
    assert provider_domain(target) == "example.com"


@pytest.mark.asyncio
async def test_target_normalization_blocks_private_resolution(monkeypatch):
    async def resolved(*_args, **_kwargs):
        return ["127.0.0.1"]

    monkeypatch.setattr("app.services.targets.normalization._resolve", resolved)
    with pytest.raises(InvalidTargetError):
        await normalize_target("https://example.test")


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", [
    ShodanProvider(ProviderSettings(name="shodan", api_key="key", endpoint="https://example.test")),
    AbuseIPDBProvider(ProviderSettings(name="abuse", api_key="key", endpoint="https://example.test")),
    IPInfoProvider(ProviderSettings(name="ipinfo", api_key="key", endpoint="https://example.test")),
    CensysProvider(ProviderSettings(name="censys", api_key="pat", endpoint="https://example.test")),
])
async def test_ip_providers_reject_urls_before_request(provider):
    transport = httpx.MockTransport(lambda request: pytest.fail(f"unexpected request {request.url}"))
    async with httpx.AsyncClient(transport=transport) as client:
        result = await provider.lookup(client, "https://example.com/")
    assert not result.success


@pytest.mark.asyncio
async def test_censys_uses_platform_host_ip_endpoint_and_bearer_headers():
    seen = {}
    def handler(request):
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["headers"] = request.headers
        return httpx.Response(200, json={"result": {"services": [{"service_name": "https"}]}})

    provider = CensysProvider(ProviderSettings(name="censys", api_key="pat", endpoint="https://api.platform.censys.io/v3/global"))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await provider.lookup(client, "8.8.8.8")
    assert result.success
    assert seen["url"] == "https://api.platform.censys.io/v3/global/asset/host/8.8.8.8"
    assert seen["auth"] == "Bearer pat"
    assert seen["headers"]["accept"] == "application/vnd.censys.api.v3.host.v1+json"
    assert "x-organization-id" not in {key.lower() for key in seen["headers"].keys()}


@pytest.mark.asyncio
async def test_censys_sends_required_accept_and_optional_organization_header():
    seen = {}
    def handler(request):
        seen["headers"] = request.headers
        return httpx.Response(200, json={"services": []})

    provider = CensysProvider(ProviderSettings(name="censys", api_key="pat", endpoint="https://api.platform.censys.io/v3/global", extra={"organization_id": "org-123"}))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert (await provider.lookup(client, "1.1.1.1")).success
    assert seen["headers"]["authorization"] == "Bearer pat"
    assert seen["headers"]["accept"] == "application/vnd.censys.api.v3.host.v1+json"
    assert seen["headers"]["x-organization-id"] == "org-123"


@pytest.mark.asyncio
async def test_censys_skips_platform_failures_without_crashing():
    for status, reason in ((401, "unauthorized"), (403, "forbidden"), (404, "not_found"), (422, "unprocessable_entity")):
        provider = CensysProvider(ProviderSettings(name="censys", api_key="pat", endpoint="https://api.platform.censys.io/v3/global"))
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _request, status=status: httpx.Response(status, text="error"))) as client:
            result = await provider.lookup(client, "8.8.8.8")
        assert not result.success
        assert result.raw == {"skipped": True, "reason": reason}


@pytest.mark.asyncio
async def test_censys_timeout_is_a_structured_skip():
    provider = CensysProvider(ProviderSettings(name="censys", api_key="pat", endpoint="https://api.platform.censys.io/v3/global"))
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: (_ for _ in ()).throw(httpx.ReadTimeout("timeout")))) as client:
        result = await provider.lookup(client, "8.8.8.8")
    assert not result.success
    assert result.raw == {"skipped": True, "reason": "timeout"}


@pytest.mark.asyncio
async def test_domain_providers_strip_full_urls():
    seen = []
    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        urlscan = UrlScanProvider(ProviderSettings(name="urlscan", endpoint="https://urlscan.io/api/v1"))
        builtwith = BuiltWithProvider(ProviderSettings(name="builtwith", api_key="key", endpoint="https://api.builtwith.com"))
        assert (await urlscan.lookup(client, "https://www.example.com/path")).success
        assert (await builtwith.lookup(client, "https://www.example.com/path")).success
    assert any("domain%3Aexample.com" in url for url in seen)
    assert any("LOOKUP=example.com" in url for url in seen)


@pytest.mark.asyncio
async def test_virustotal_uses_v3_endpoint_for_url_domain_ip_and_file_hash():
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0}}}})

    provider = VirusTotalProvider(ProviderSettings(name="virustotal", api_key="vt-key", endpoint="https://www.virustotal.com/api/v3"))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        url_result = await provider.lookup(client, "https://www.example.com/path?a=1", context={"target_kind": "url"})
        domain_result = await provider.lookup(client, "www.example.com", context={"target_kind": "domain"})
        ip_result = await provider.lookup(client, "8.8.8.8", context={"target_kind": "public_ip"})
        file_hash = "a" * 64
        file_result = await provider.lookup(client, file_hash, context={"target_kind": "file"})

    url_id = base64.urlsafe_b64encode("https://www.example.com/path?a=1".encode()).decode().rstrip("=")
    assert seen == [
        f"/api/v3/urls/{url_id}",
        "/api/v3/domains/example.com",
        "/api/v3/ip_addresses/8.8.8.8",
        f"/api/v3/files/{file_hash}",
    ]
    assert all(result.success for result in (url_result, domain_result, ip_result, file_result))
    assert url_result.normalized[0]["classification"] == "Malicious Classification"


@pytest.mark.asyncio
async def test_virustotal_404_is_no_known_detection_not_provider_failure():
    provider = VirusTotalProvider(ProviderSettings(name="virustotal", api_key="vt-key", endpoint="https://www.virustotal.com/api/v3"))
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(404, text="not found"))) as client:
        result = await provider.lookup(client, "example.com", context={"target_kind": "domain"})
    assert result.success
    assert result.status_code == 404
    assert result.normalized[0]["classification"] == "No Known Detection"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "reason"),
    [(401, "invalid_api_key"), (403, "restricted_plan_or_action"), (429, "rate_limited")],
)
async def test_virustotal_auth_plan_and_rate_limit_errors_are_structured_skips(status_code, reason):
    provider = VirusTotalProvider(ProviderSettings(name="virustotal", api_key="vt-key", endpoint="https://www.virustotal.com/api/v3"))
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(status_code, text="provider error"))) as client:
        result = await provider.lookup(client, "example.com", context={"target_kind": "domain"})
    assert not result.success
    assert result.status_code == status_code
    assert result.raw["skipped"] is True
    assert result.raw["reason"] == reason


@pytest.mark.asyncio
async def test_virustotal_file_lookup_requires_hash_and_never_uploads_source():
    provider = VirusTotalProvider(ProviderSettings(name="virustotal", api_key="vt-key", endpoint="https://www.virustotal.com/api/v3"))
    transport = httpx.MockTransport(lambda request: pytest.fail(f"unexpected request {request.url}"))
    async with httpx.AsyncClient(transport=transport) as client:
        result = await provider.lookup(client, "print('private source')", context={"target_kind": "file"})
    assert not result.success
    assert result.raw["reason"] == "unsupported_target"


@pytest.mark.asyncio
async def test_ai_uses_fallback_after_primary_failure(monkeypatch):
    service = AIExplanationService()
    calls = []
    async def request(*args, **kwargs):
        calls.append(args[0])
        if "nvidia" in args[0]:
            raise httpx.TimeoutException("timeout")
        return "Fallback explanation"

    monkeypatch.setattr("app.services.ai.explanations.settings.NVIDIA_API_KEY", "primary")
    monkeypatch.setattr("app.services.ai.explanations.settings.OPENROUTER_API_KEY", "fallback")
    monkeypatch.setattr(service, "_request", request)
    result = await service.explain_scan(target="https://example.com", findings=[], score=2.0)
    assert result["provider"] == "openrouter"
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_raw_findings_are_preserved_when_correlation_groups_them():
    scanner = ScanOrchestrator()
    raw = [
        RawFinding(type="header", title="Missing CSP", description="missing", raw_data={"rule_id": "VN-HTTP-MISSING-CSP"}, target="https://example.com"),
        RawFinding(type="header", title="Missing XFO", description="missing", raw_data={"rule_id": "VN-HTTP-MISSING-XFO"}, target="https://example.com"),
    ]
    correlated = await scanner.correlation_engine.correlate(raw)
    displayed = scanner._display_findings(raw, correlated)
    assert len(correlated) < len(displayed)
    assert [item.contributing_rule_ids[0] for item in displayed] == ["VN-HTTP-MISSING-CSP", "VN-HTTP-MISSING-XFO"]
