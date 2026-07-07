from __future__ import annotations

from typing import Any

import httpx

from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider


class CIRCLProvider(SimpleJsonProvider):
    provider_name = "CIRCL"
    path = "search"

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        response = await client.get(self.settings.endpoint.rstrip("/") + f"/search/{query}")
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, list):
            payload = []
        items = []
        for item in payload[:limit]:
            items.append({
                "identifier": item.get("id") or query,
                "cve_id": item.get("id"),
                "summary": item.get("summary"),
                "cvss_score": item.get("cvss"),
                "references": item.get("references") or [],
                "raw": item,
            })
        return normalize_results(self.provider_name, query, items, raw={"items": payload}, status_code=response.status_code)


from app.services.integrations.base import normalize_results


register_simple_provider("circl", lambda settings_: CIRCLProvider(settings_))