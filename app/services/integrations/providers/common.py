from __future__ import annotations

from typing import Any

import httpx

from app.services.integrations.base import ProviderAdapter, ProviderSettings, normalize_results


class SimpleJsonProvider(ProviderAdapter):
    path: str = ""
    method: str = "GET"
    query_param: str = "query"
    item_key: str | None = None
    extra_params: dict[str, Any] = {}
    allowed_context_params: set[str] = set()

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        url = self._build_url(query, context)
        response = await self._request(client, url, query, context=context, limit=limit)
        return response

    def _build_url(self, query: str, context: dict[str, Any] | None) -> str:
        endpoint = (self.settings.endpoint or "").rstrip("/")
        if self.path:
            return f"{endpoint}/{self.path.lstrip('/')}"
        return endpoint

    async def _request(self, client: httpx.AsyncClient, url: str, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        params = {self.query_param: query, **self.extra_params}
        if context:
            params.update({key: value for key, value in context.items() if key in self.allowed_context_params and value is not None})
        if self.method.upper() == "POST":
            response = await client.post(url, json=params)
        else:
            response = await client.get(url, params=params)
        response.raise_for_status()
        payload = response.json()
        items = self._extract_items(payload, query, limit=limit)
        return normalize_results(self.provider_name, query, items, raw=payload, status_code=response.status_code)

    def _extract_items(self, payload: Any, query: str, *, limit: int) -> list[dict[str, Any]]:
        data = payload
        if self.item_key and isinstance(payload, dict):
            data = payload.get(self.item_key, [])
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return []
        return [self._normalize_item(item, query) for item in data[:limit]]

    def _normalize_item(self, item: dict[str, Any], query: str) -> dict[str, Any]:
        return {
            "identifier": item.get("id") or item.get("identifier") or query,
            "summary": item.get("summary") or item.get("description") or item.get("title"),
            "cvss_score": item.get("cvss") or item.get("cvss_score"),
            "epss_score": item.get("epss") or item.get("epss_score"),
            "kev": bool(item.get("kev") or item.get("known_exploited")),
            "vendor": item.get("vendor") or item.get("source"),
            "references": item.get("references") or item.get("links") or [],
            "exploitability": item.get("exploitability"),
            "raw": item,
        }


def register_simple_provider(name: str, factory):
    from app.services.integrations.registry import registry

    registry.register(name, factory)
