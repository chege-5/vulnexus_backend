from __future__ import annotations

from typing import Any

import httpx

from app.services.integrations.base import normalize_results
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider


class SSLLabsProvider(SimpleJsonProvider):
    provider_name = "SSL_LABS"
    path = "analyze"

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        response = await client.get(self.settings.endpoint.rstrip("/") + "/analyze", params={"host": query, "fromCache": "on", "all": "done"})
        response.raise_for_status()
        payload = response.json()
        items = []
        for endpoint in (payload.get("endpoints") or [])[:limit]:
            grade = endpoint.get("grade")
            if not grade:
                continue
            items.append({
                "identifier": query,
                "summary": f"SSL Labs grade {grade}",
                "exploitability": "transport-hardening",
                "raw": endpoint,
            })
        return normalize_results(self.provider_name, query, items, raw=payload, status_code=response.status_code)


register_simple_provider("ssllabs", lambda settings_: SSLLabsProvider(settings_))