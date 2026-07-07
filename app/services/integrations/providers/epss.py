from __future__ import annotations

from typing import Any

import httpx

from app.config import settings
from app.services.integrations.base import normalize_results
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider


class EPSSProvider(SimpleJsonProvider):
    provider_name = "EPSS"
    path = ""
    query_param = "cve"

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        response = await client.get(self.settings.endpoint or settings.EPSS_API_URL, params={"cve": query})
        response.raise_for_status()
        payload = response.json()
        items = []
        for item in (payload.get("data") or [])[:limit]:
            items.append({
                "identifier": item.get("cve") or query,
                "cve_id": item.get("cve"),
                "summary": f"EPSS probability {item.get('epss')} percentile {item.get('percentile')}",
                "epss_score": _float_or_none(item.get("epss")),
                "raw": item,
            })
        return normalize_results(self.provider_name, query, items, raw=payload, status_code=response.status_code)


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


register_simple_provider("epss", lambda settings_: EPSSProvider(settings_))