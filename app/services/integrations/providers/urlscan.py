from __future__ import annotations

from typing import Any

import httpx

from app.services.integrations.base import normalize_results
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider
from app.services.integrations.providers.target_validation import domain_from_value


class UrlScanProvider(SimpleJsonProvider):
    provider_name = "URLSCAN"

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        domain = domain_from_value(query)
        if not domain:
            return normalize_results(self.provider_name, query, [], error="urlscan requires a domain")
        headers = {"API-Key": self.settings.api_key} if self.settings.api_key else {}
        response = await client.get(f"{self.settings.endpoint.rstrip('/')}/search/", params={"q": f"domain:{domain}"}, headers=headers)
        if response.status_code >= 400:
            return normalize_results(self.provider_name, query, [], raw={"status": response.status_code}, status_code=response.status_code, error=response.text)
        payload = response.json()
        items = [{"identifier": domain, "summary": "urlscan.io search result", "vendor": "urlscan", "raw": payload}]
        return normalize_results(self.provider_name, domain, items, raw=payload, status_code=response.status_code)


register_simple_provider("urlscan", lambda settings_: UrlScanProvider(settings_))
