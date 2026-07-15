from __future__ import annotations

from typing import Any

import httpx

from app.services.integrations.base import normalize_results
from app.services.integrations.cache import cache
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider
from app.services.integrations.providers.target_validation import domain_from_value
from app.services.models.pipeline import ProviderResponse
from app.utils.logger import get_logger

logger = get_logger(__name__)


class BuiltWithProvider(SimpleJsonProvider):
    provider_name = "BUILTWITH"

    async def cached_lookup(self, query: str, *, context: dict[str, Any] | None = None, limit: int = 5) -> ProviderResponse:
        domain = domain_from_value(query)
        if not domain:
            return normalize_results(self.provider_name, query, [], error="BuiltWith requires a domain")
        key = cache.build_key("builtwith", domain)
        cached = await cache.get_json(key)
        if cached is not None:
            logger.info("provider=builtwith action=domain_lookup domain=%s cache_hit=true status=%s", domain, cached.get("status_code"))
            return ProviderResponse(provider=self.provider_name, query=domain, cached=True, success=bool(cached.get("success", True)), enabled=self.enabled, normalized=list(cached.get("normalized") or []), raw=dict(cached.get("raw") or {}), status_code=cached.get("status_code"), error=cached.get("error"))
        response = await super().cached_lookup(domain, context=context, limit=limit)
        if response.success:
            await cache.set_json(key, {"success": True, "normalized": response.normalized, "raw": response.raw, "status_code": response.status_code}, ttl=self.settings.extra.get("builtwith_cache_ttl_seconds"))
        elif response.status_code == 429:
            logger.warning("BuiltWith enrichment skipped: rate limited")
            await cache.set_json(key, {"success": False, "normalized": [], "raw": {"status": 429}, "status_code": 429, "error": "BuiltWith rate limited"}, ttl=600)
        return response

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        domain = domain_from_value(query)
        if not self.settings.api_key:
            return normalize_results(self.provider_name, query, [], error="missing api key")
        if not domain:
            return normalize_results(self.provider_name, query, [], error="BuiltWith requires a domain")
        response = await client.get(
            f"{self.settings.endpoint.rstrip('/')}/free1/api.json",
            params={"KEY": self.settings.api_key, "LOOKUP": domain},
        )
        logger.info("provider=builtwith action=domain_lookup domain=%s cache_hit=false status=%s", domain, response.status_code)
        if response.status_code >= 400:
            return normalize_results(self.provider_name, query, [], raw={"status": response.status_code}, status_code=response.status_code, error=response.text)
        payload = response.json()
        items = [{"identifier": domain, "summary": "BuiltWith technology profile", "vendor": "BuiltWith", "raw": payload}]
        return normalize_results(self.provider_name, domain, items, raw=payload, status_code=response.status_code)


register_simple_provider("builtwith", lambda settings_: BuiltWithProvider(settings_))
