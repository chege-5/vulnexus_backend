from __future__ import annotations

from typing import Any

import httpx

from app.services.integrations.base import normalize_results
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider


class SecurityTrailsProvider(SimpleJsonProvider):
    provider_name = "SECURITYTRAILS"

    def _auth_headers(self) -> dict[str, str]:
        return {"APIKEY": self.settings.api_key} if self.settings.api_key else {}

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        if not self.settings.api_key:
            return normalize_results(self.provider_name, query, [], error="missing api key")
        response = await client.get(f"{self.settings.endpoint.rstrip('/')}/domain/{query}", headers=self._auth_headers())
        if response.status_code >= 400:
            return normalize_results(self.provider_name, query, [], raw={"status": response.status_code}, status_code=response.status_code, error=response.text)
        payload = response.json()
        items = [{"identifier": query, "summary": payload.get("description") or payload.get("whois").get("registrant") if isinstance(payload.get("whois"), dict) else None, "vendor": "SecurityTrails", "raw": payload}]
        return normalize_results(self.provider_name, query, items, raw=payload, status_code=response.status_code)


register_simple_provider("securitytrails", lambda settings_: SecurityTrailsProvider(settings_))