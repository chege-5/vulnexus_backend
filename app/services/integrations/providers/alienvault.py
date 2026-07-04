from __future__ import annotations

from typing import Any

import httpx

from app.services.integrations.base import normalize_results
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider


class AlienVaultProvider(SimpleJsonProvider):
    provider_name = "ALIENVAULT_OTX"

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        if not self.settings.api_key:
            return normalize_results(self.provider_name, query, [], error="missing api key")
        response = await client.get(f"{self.settings.endpoint.rstrip('/')}/indicators/domain/{query}/general", headers={"X-OTX-API-KEY": self.settings.api_key})
        if response.status_code >= 400:
            return normalize_results(self.provider_name, query, [], raw={"status": response.status_code}, status_code=response.status_code, error=response.text)
        payload = response.json()
        items = [{"identifier": query, "summary": payload.get("pulse_info", {}).get("count") and "AlienVault OTX indicator present", "vendor": "AlienVault OTX", "raw": payload}]
        return normalize_results(self.provider_name, query, items, raw=payload, status_code=response.status_code)


register_simple_provider("alienvault", lambda settings_: AlienVaultProvider(settings_))