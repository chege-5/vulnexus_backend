from __future__ import annotations

from uuid import uuid4

import httpx
import pytest

from app.services.integrations.base import ProviderSettings
from app.services.integrations.providers.shodan import PLAN_RESTRICTED_MESSAGE, ShodanProvider
from app.services.models.pipeline import ProviderResponse, ScanContext, ScanTarget
from app.services.scanners.reputation import ReputationScanner
from app.services.targets.normalization import NormalizedTarget
from app.services.report_generator import generate_html_report


def _provider(**extra) -> ShodanProvider:
    return ShodanProvider(
        ProviderSettings(
            name="shodan",
            api_key="test-key",
            endpoint="https://api.shodan.io",
            extra={"plan": "free", "host_lookup_enabled": True, **extra},
        )
    )


@pytest.mark.asyncio
async def test_free_plan_host_lookup_uses_only_the_public_ip_endpoint():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        assert request.url.path == "/shodan/host/8.8.8.8"
        return httpx.Response(200, json={"org": "Example Org", "data": []})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await _provider().lookup(client, "8.8.8.8")

    assert result.success
    assert seen == ["https://api.shodan.io/shodan/host/8.8.8.8?key=test-key"]
    assert all("/shodan/banners" not in url and "/shodan/data" not in url and "/org" not in url for url in seen)


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["https://example.com/path", "example.com"])
async def test_host_lookup_never_receives_a_url_or_hostname(target: str):
    transport = httpx.MockTransport(lambda request: pytest.fail(f"unexpected request {request.url}"))
    async with httpx.AsyncClient(transport=transport) as client:
        result = await _provider().lookup(client, target)

    assert result.success is False
    assert result.raw["reason"] == "invalid_target"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "body", "reason"),
    [
        (401, "invalid key", "invalid_or_missing_api_key"),
        (403, "forbidden", "forbidden_or_free_plan_restricted"),
        (404, "not found", "no_shodan_data_for_ip"),
        (429, "rate limit", "rate_or_credit_limited"),
        (400, "out of credits", "rate_or_credit_limited"),
    ],
)
async def test_free_plan_failures_are_structured_skips(status_code: int, body: str, reason: str):
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(status_code, text=body))) as client:
        result = await _provider().lookup(client, "1.1.1.1")

    assert result.success is False
    assert result.status_code == status_code
    assert result.raw["skipped"] is True
    assert result.raw["reason"] == reason
    if status_code == 403:
        assert result.raw["message"] == PLAN_RESTRICTED_MESSAGE


@pytest.mark.asyncio
async def test_shodan_timeout_does_not_crash_the_scan_provider():
    def handler(_request: httpx.Request):
        raise httpx.ReadTimeout("timeout")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await _provider().lookup(client, "1.1.1.1")

    assert result.success is False
    assert result.raw["reason"] == "timeout"


@pytest.mark.asyncio
async def test_api_info_validates_key_without_using_host_or_enterprise_endpoints():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json={"plan": "free", "query_credits": 0})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await _provider().api_info(client)

    assert result.success is True
    assert seen == ["/api-info"]


@pytest.mark.asyncio
async def test_reputation_metadata_exposes_honest_shodan_free_plan_status(monkeypatch):
    normalized = NormalizedTarget(
        original="https://example.com",
        normalized_url="https://example.com/",
        scheme="https",
        hostname="example.com",
        registered_domain="example.com",
        port=None,
        path="/",
        query="",
        resolved_ips=["8.8.8.8"],
        public_ips=["8.8.8.8"],
    )

    async def lookup(*_args, **_kwargs):
        return [
            ProviderResponse(
                provider="SHODAN",
                query="8.8.8.8",
                success=False,
                status_code=403,
                raw={
                    "skipped": True,
                    "reason": "forbidden_or_free_plan_restricted",
                    "message": PLAN_RESTRICTED_MESSAGE,
                },
                error=PLAN_RESTRICTED_MESSAGE,
            )
        ]

    monkeypatch.setattr("app.services.scanners.reputation.normalize_target", lambda *_args, **_kwargs: _async_value(normalized))
    monkeypatch.setattr("app.services.scanners.reputation.integration_manager.lookup", lookup)

    target = ScanTarget(kind="url", value="https://example.com")
    context = ScanContext(scan_id=uuid4(), scan_type="url", target=target)
    result = await ReputationScanner().scan(target, context)

    assert result.findings == []
    assert result.metadata["provider_statuses"] == [
        {
            "provider": "SHODAN",
            "status": "skipped",
            "success": False,
            "status_code": 403,
            "reason": "forbidden_or_free_plan_restricted",
            "message": PLAN_RESTRICTED_MESSAGE,
        }
    ]


def test_report_renders_provider_restriction_honestly():
    html = generate_html_report(
        scan_id="scan-id",
        target="https://example.com",
        scan_type="url",
        overall_score=0,
        vulnerabilities=[],
        cve_details=[],
        provider_statuses=[{"provider": "SHODAN", "status": "skipped", "message": PLAN_RESTRICTED_MESSAGE}],
    )

    assert "External Intelligence Provider Status" in html
    assert PLAN_RESTRICTED_MESSAGE in html


async def _async_value(value):
    return value
