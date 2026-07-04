from __future__ import annotations

from typing import Any

import httpx

from app.config import settings
from app.services.integrations.base import ProviderSettings, normalize_results
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider


class NVDProvider(SimpleJsonProvider):
    provider_name = "NVD"
    path = ""
    query_param = "keywordSearch"
    item_key = "vulnerabilities"

    def _auth_headers(self) -> dict[str, str]:
        if not self.settings.api_key:
            return {}
        return {"apiKey": self.settings.api_key}

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        url = (self.settings.endpoint or getattr(settings, "NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")).rstrip("/")
        params = {"keywordSearch": query, "resultsPerPage": min(max(limit, 1), 20)}
        response = await client.get(url, params=params, headers=self._auth_headers())
        response.raise_for_status()
        payload = response.json()
        items = []
        for item in (payload.get("vulnerabilities") or [])[:limit]:
            cve_data = item.get("cve", {})
            descriptions = cve_data.get("descriptions", [])
            summary = next((entry.get("value") for entry in descriptions if entry.get("lang") == "en"), None)
            items.append({
                "identifier": cve_data.get("id") or query,
                "cve_id": cve_data.get("id"),
                "summary": summary,
                "cvss_score": _extract_cvss(cve_data.get("metrics", {})),
                "references": [ref.get("url") for ref in cve_data.get("references", []) if ref.get("url")],
                "vendor": "NVD",
                "raw": cve_data,
            })
        return normalize_results(self.provider_name, query, items, raw=payload, status_code=response.status_code)


def _extract_cvss(metrics: dict[str, Any]) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            return entries[0].get("cvssData", {}).get("baseScore")
    return None


register_simple_provider("nvd", lambda settings_: NVDProvider(settings_))