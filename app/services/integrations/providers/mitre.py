from __future__ import annotations

import httpx

from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider


class MITREProvider(SimpleJsonProvider):
    provider_name = "MITRE"
    path = ""

    async def health_check(self, client: httpx.AsyncClient) -> dict[str, object]:
        return {"provider": self.provider_name, "enabled": self.enabled, "healthy": True, "endpoint": self.settings.endpoint, "message": "CWE/CVE mapping handled locally"}

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict | None = None, limit: int = 5):
        return await super().lookup(client, query, context=context, limit=limit)


register_simple_provider("mitre", lambda settings_: MITREProvider(settings_))