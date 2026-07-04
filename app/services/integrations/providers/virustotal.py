from __future__ import annotations

from typing import Any

import httpx

from app.services.integrations.base import normalize_results
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider


class VirusTotalProvider(SimpleJsonProvider):
    provider_name = "VIRUSTOTAL"

    def _auth_headers(self) -> dict[str, str]:
        return {"x-apikey": self.settings.api_key} if self.settings.api_key else {}

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        if not self.settings.api_key:
            return normalize_results(self.provider_name, query, [], error="missing api key")
        response = await client.get(f"{self.settings.endpoint.rstrip('/')}/domains/{query}", headers=self._auth_headers())
        if response.status_code >= 400:
            return normalize_results(self.provider_name, query, [], raw={"status": response.status_code}, status_code=response.status_code, error=response.text)
        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {}) if isinstance(payload, dict) else {}
        items = [{"identifier": query, "summary": attributes.get("reputation") and f"Reputation {attributes.get('reputation')}", "vendor": "VirusTotal", "raw": payload}]
        return normalize_results(self.provider_name, query, items, raw=payload, status_code=response.status_code)


register_simple_provider("virustotal", lambda settings_: VirusTotalProvider(settings_))