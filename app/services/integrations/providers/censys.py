from __future__ import annotations

from typing import Any

import base64
import httpx

from app.services.integrations.base import normalize_results
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider


class CensysProvider(SimpleJsonProvider):
    provider_name = "CENSYS"

    def _auth_headers(self) -> dict[str, str]:
        if not self.settings.api_key:
            return {}
        api_id = self.settings.extra.get("api_id") or self.settings.name
        secret = self.settings.api_key
        encoded = base64.b64encode(f"{api_id}:{secret}".encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        if not self.settings.api_key:
            return normalize_results(self.provider_name, query, [], error="missing api key")
        response = await client.get(f"{self.settings.endpoint.rstrip('/')}/hosts/{query}", headers=self._auth_headers())
        if response.status_code >= 400:
            return normalize_results(self.provider_name, query, [], raw={"status": response.status_code}, status_code=response.status_code, error=response.text)
        payload = response.json()
        items = [{
            "identifier": query,
            "summary": payload.get("result", {}).get("services", [{}])[0].get("service_name") if payload.get("result") else None,
            "vendor": "Censys",
            "raw": payload,
        }]
        return normalize_results(self.provider_name, query, items, raw=payload, status_code=response.status_code)


register_simple_provider("censys", lambda settings_: CensysProvider(settings_))