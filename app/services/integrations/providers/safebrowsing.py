from __future__ import annotations

from typing import Any

import httpx

from app.services.integrations.base import normalize_results
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider


class SafeBrowsingProvider(SimpleJsonProvider):
    provider_name = "GOOGLE_SAFE_BROWSING"

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        if not self.settings.api_key:
            return normalize_results(self.provider_name, query, [], error="missing api key")
        payload = {
            "client": {"clientId": "vulnexus", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": query}],
            },
        }
        response = await client.post(f"{self.settings.endpoint.rstrip('/')}/threatMatches:find?key={self.settings.api_key}", json=payload)
        if response.status_code >= 400:
            return normalize_results(self.provider_name, query, [], raw={"status": response.status_code}, status_code=response.status_code, error=response.text)
        body = response.json()
        matches = body.get("matches") or []
        items = [{"identifier": query, "summary": "URL flagged by Google Safe Browsing" if matches else "No match", "vendor": "Google", "raw": body}]
        return normalize_results(self.provider_name, query, items, raw=body, status_code=response.status_code)


register_simple_provider("safebrowsing", lambda settings_: SafeBrowsingProvider(settings_))