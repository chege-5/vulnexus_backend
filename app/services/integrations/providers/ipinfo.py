from __future__ import annotations

from typing import Any

import httpx

from app.services.integrations.base import normalize_results
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider
from app.services.integrations.providers.target_validation import public_ip_or_none


class IPInfoProvider(SimpleJsonProvider):
    provider_name = "IPINFO"

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.settings.api_key}"} if self.settings.api_key else {}

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        ip = public_ip_or_none(query)
        if not ip:
            return normalize_results(self.provider_name, query, [], error="ipinfo requires a public IP address")
        response = await client.get(f"{self.settings.endpoint.rstrip('/')}/{ip}/json", headers=self._auth_headers())
        if response.status_code >= 400:
            return normalize_results(self.provider_name, query, [], raw={"status": response.status_code}, status_code=response.status_code, error=response.text)
        payload = response.json()
        items = [{"identifier": ip, "summary": payload.get("org") or payload.get("city") or payload.get("country"), "vendor": "IPinfo", "raw": payload}]
        return normalize_results(self.provider_name, ip, items, raw=payload, status_code=response.status_code)


register_simple_provider("ipinfo", lambda settings_: IPInfoProvider(settings_))
