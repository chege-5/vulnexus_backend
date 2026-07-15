from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import httpx

from app.core.http_client import create_async_client
from app.config import settings
from app.services.integrations.base import ProviderAdapter, ProviderSettings, to_intelligence_result
from app.services.integrations.health import ProviderHealth
from app.services.integrations.registry import registry
from app.services.models.pipeline import IntelligenceResult, ProviderResponse
from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass(slots=True)
class LookupRequest:
    query: str
    limit: int = 5
    context: dict[str, Any] | None = None


class IntegrationManager:
    def __init__(self) -> None:
        self._providers: dict[str, ProviderAdapter] = {}
        self._health: dict[str, ProviderHealth] = {}
        self._initialized = False

    def configure(self) -> None:
        if self._initialized:
            return

        from app.services.integrations import providers as _provider_modules  # noqa: F401

        for name, factory in registry.items().items():
            provider_settings = self._settings_for(name)
            if provider_settings is None or not provider_settings.enabled:
                continue
            provider = factory(provider_settings)
            self._providers[provider.provider_name.lower()] = provider

        self._initialized = True

    async def initialize(self) -> dict[str, ProviderHealth]:
        self.configure()
        await self.health_check_all()
        return dict(self._health)

    def _settings_for(self, provider_key: str) -> ProviderSettings | None:
        provider_key = provider_key.lower()
        enabled, api_key, endpoint = self._provider_env(provider_key)
        if enabled is None:
            return None
        return ProviderSettings(
            name=provider_key,
            enabled=enabled,
            api_key=api_key,
            endpoint=endpoint,
            timeout_seconds=self._timeout_for(provider_key),
            retry_attempts=settings.INTELLIGENCE_RETRY_ATTEMPTS,
            retry_backoff_seconds=settings.INTELLIGENCE_RETRY_BACKOFF_SECONDS,
            cache_ttl_seconds=settings.INTELLIGENCE_CACHE_TTL_SECONDS,
            extra=(
                {"organization_id": settings.CENSYS_ORGANIZATION_ID}
                if provider_key == "censys"
                else {
                    "plan": settings.SHODAN_PLAN,
                    "host_lookup_enabled": settings.SHODAN_ENABLE_HOST_LOOKUP,
                    "search_enabled": settings.SHODAN_ENABLE_SEARCH,
                    "on_demand_scan_enabled": settings.SHODAN_ENABLE_ON_DEMAND_SCAN,
                    "streaming_enabled": settings.SHODAN_ENABLE_STREAMING,
                    "bulk_data_enabled": settings.SHODAN_ENABLE_BULK_DATA,
                }
                if provider_key == "shodan"
                else {"builtwith_cache_ttl_seconds": settings.BUILTWITH_CACHE_TTL_SECONDS}
                if provider_key == "builtwith"
                else {"allow_file_upload": settings.VIRUSTOTAL_ALLOW_FILE_UPLOAD}
                if provider_key == "virustotal"
                else {}
            ),
        )

    def _provider_env(self, provider_key: str) -> tuple[bool | None, str | None, str | None]:
        mapping: dict[str, tuple[bool | None, str | None, str | None]] = {
            "nvd": (True, settings.NVD_API_KEY, getattr(settings, "NVD_API_URL", None)),
            "mitre": (True, None, settings.MITRE_CVE_API_URL),
            "cisa": (True, None, getattr(settings, "CISA_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")),
            "epss": (True, None, getattr(settings, "EPSS_API_URL", "https://api.first.org/data/v1/epss")),
            "ssllabs": (True, None, settings.SSL_LABS_API_URL),
            "circl": (True, None, settings.CVE_CIRCL_API_URL),
            "shodan": (settings.SHODAN_ENABLED, settings.SHODAN_API_KEY, getattr(settings, "SHODAN_API_URL", "https://api.shodan.io")),
            "censys": (settings.CENSYS_ENABLED, settings.CENSYS_PAT, settings.CENSYS_API_BASE_URL),
            "securitytrails": (getattr(settings, "SECURITYTRAILS_ENABLED", False), getattr(settings, "SECURITYTRAILS_API_KEY", None), getattr(settings, "SECURITYTRAILS_API_URL", "https://api.securitytrails.com/v1")),
            "virustotal": (settings.VIRUSTOTAL_ENABLED, settings.VIRUSTOTAL_API_KEY, getattr(settings, "VIRUSTOTAL_API_URL", "https://www.virustotal.com/api/v3")),
            "abuseipdb": (getattr(settings, "ABUSEIPDB_ENABLED", False), getattr(settings, "ABUSEIPDB_API_KEY", None), getattr(settings, "ABUSEIPDB_API_URL", "https://api.abuseipdb.com/api/v2")),
            "safebrowsing": (getattr(settings, "GOOGLE_SAFE_BROWSING_ENABLED", False), getattr(settings, "GOOGLE_SAFE_BROWSING_API_KEY", None), getattr(settings, "GOOGLE_SAFE_BROWSING_API_URL", "https://safebrowsing.googleapis.com/v4")),
            "ipinfo": (getattr(settings, "IPINFO_ENABLED", False), getattr(settings, "IPINFO_API_KEY", None), getattr(settings, "IPINFO_API_URL", "https://ipinfo.io")),
            "builtwith": (getattr(settings, "BUILTWITH_ENABLED", False), getattr(settings, "BUILTWITH_API_KEY", None), getattr(settings, "BUILTWITH_API_URL", "https://api.builtwith.com")),
            "wappalyzer": (getattr(settings, "WAPPALYZER_ENABLED", False), getattr(settings, "WAPPALYZER_API_KEY", None), getattr(settings, "WAPPALYZER_API_URL", "https://api.wappalyzer.com")),
            "urlscan": (getattr(settings, "URLSCAN_ENABLED", False), getattr(settings, "URLSCAN_API_KEY", None), getattr(settings, "URLSCAN_API_URL", "https://urlscan.io/api/v1")),
            "greynoise": (getattr(settings, "GREYNOISE_ENABLED", False), getattr(settings, "GREYNOISE_API_KEY", None), getattr(settings, "GREYNOISE_API_URL", "https://api.greynoise.io/v3")),
            "alienvault": (getattr(settings, "ALIENVAULT_ENABLED", False), getattr(settings, "ALIENVAULT_OTX_API_KEY", None), getattr(settings, "ALIENVAULT_OTX_API_URL", "https://otx.alienvault.com/api/v1")),
            "cloudflare": (getattr(settings, "CLOUDFLARE_ENABLED", False), getattr(settings, "CLOUDFLARE_API_KEY", None), getattr(settings, "CLOUDFLARE_API_URL", None)),
        }
        return mapping.get(provider_key, (None, None, None))

    def _timeout_for(self, provider_key: str) -> int | float:
        if provider_key == "censys":
            return settings.CENSYS_TIMEOUT_SECONDS
        if provider_key == "shodan":
            return settings.SHODAN_TIMEOUT_SECONDS
        if provider_key == "virustotal":
            return settings.VIRUSTOTAL_TIMEOUT_SECONDS
        return settings.INTELLIGENCE_REQUEST_TIMEOUT_SECONDS

    @property
    def providers(self) -> list[ProviderAdapter]:
        self.configure()
        return list(self._providers.values())

    async def health_check_all(self) -> dict[str, ProviderHealth]:
        self.configure()
        if not self._providers:
            return {}

        async with create_async_client(timeout=settings.INTELLIGENCE_REQUEST_TIMEOUT_SECONDS, headers={"User-Agent": "Vulnexus/1.0"}) as client:
            checks = await asyncio.gather(*(self._health_for(provider, client) for provider in self._providers.values()), return_exceptions=True)

        health: dict[str, ProviderHealth] = {}
        for item in checks:
            if isinstance(item, ProviderHealth):
                health[item.provider.lower()] = item
        self._health = health
        return health

    async def _health_for(self, provider: ProviderAdapter, client: httpx.AsyncClient) -> ProviderHealth:
        try:
            payload = await provider.health_check(client)
            health = ProviderHealth(
                provider=provider.provider_name,
                enabled=provider.enabled,
                healthy=bool(payload.get("healthy", True)),
                message=payload.get("message", "ok"),
                endpoint=payload.get("endpoint") or provider.settings.endpoint,
                details=payload,
            )
            if not health.healthy:
                logger.warning("Provider unhealthy: %s - %s", provider.provider_name, health.message)
            return health
        except Exception as exc:  # pragma: no cover - provider/network failures should not stop startup
            logger.warning("Provider health check failed for %s: %s", provider.provider_name, exc)
            return ProviderHealth(provider=provider.provider_name, enabled=provider.enabled, healthy=False, message=str(exc), endpoint=provider.settings.endpoint)

    async def lookup(self, query: str, *, limit: int = 5, context: dict[str, Any] | None = None, providers: Iterable[str] | None = None) -> list[ProviderResponse]:
        self.configure()
        if not self._providers:
            return []

        selected = self._select_providers(providers)
        if not selected:
            return []

        tasks = [provider.cached_lookup(query, context=context, limit=limit) for provider in selected]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        normalized: list[ProviderResponse] = []
        for result in results:
            if isinstance(result, Exception):
                logger.warning("Provider lookup failed: %s", result)
                continue
            normalized.append(result)
        return normalized

    async def enrich_intelligence(self, query: str, *, limit: int = 5, context: dict[str, Any] | None = None, providers: Iterable[str] | None = None) -> list[IntelligenceResult]:
        responses = await self.lookup(query, limit=limit, context=context, providers=providers)
        return [to_intelligence_result(response, query=query) for response in responses if response.success or response.cached]

    def _select_providers(self, providers: Iterable[str] | None) -> list[ProviderAdapter]:
        if providers is None:
            return list(self._providers.values())
        wanted = {provider.lower() for provider in providers}
        return [provider for name, provider in self._providers.items() if name in wanted]

    def provider_names(self) -> list[str]:
        self.configure()
        return sorted(provider.provider_name for provider in self._providers.values())

    def health_snapshot(self) -> dict[str, ProviderHealth]:
        return dict(self._health)


integration_manager = IntegrationManager()
