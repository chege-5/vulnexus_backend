from __future__ import annotations

from typing import Any

import httpx

from app.config import settings
from app.services.integrations.base import normalize_results
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider


class CISAProvider(SimpleJsonProvider):
    provider_name = "CISA_KEV"
    path = ""
    item_key = "vulnerabilities"

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        response = await client.get(self.settings.endpoint or settings.CISA_KEV_URL)
        response.raise_for_status()
        payload = response.json()
        items = []
        lowered = query.lower()
        for item in (payload.get("vulnerabilities") or []):
            cve_id = (item.get("cveID") or "").lower()
            vuln_name = (item.get("vulnerabilityName") or "").lower()
            if lowered not in cve_id and lowered not in vuln_name:
                continue
            items.append({
                "identifier": item.get("cveID") or query,
                "cve_id": item.get("cveID"),
                "summary": item.get("vulnerabilityName"),
                "kev": True,
                "references": [item.get("notes")] if item.get("notes") else [],
                "raw": item,
            })
            if len(items) >= limit:
                break
        return normalize_results(self.provider_name, query, items, raw=payload, status_code=response.status_code)


register_simple_provider("cisa", lambda settings_: CISAProvider(settings_))