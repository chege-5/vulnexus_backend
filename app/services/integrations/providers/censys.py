from __future__ import annotations

from typing import Any

import httpx

from app.services.integrations.base import normalize_results
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider
from app.services.integrations.providers.target_validation import public_ip_or_none
from app.utils.logger import get_logger

logger = get_logger(__name__)


class CensysProvider(SimpleJsonProvider):
    provider_name = "CENSYS"

    accept_header = "application/vnd.censys.api.v3.host.v1+json"

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": self.accept_header}
        if self.settings.api_key:
            headers["Authorization"] = f"Bearer {self.settings.api_key}"
        organization_id = self.settings.extra.get("organization_id")
        if organization_id:
            headers["X-Organization-ID"] = str(organization_id)
        return headers

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        ip = public_ip_or_none(query)
        if not self.settings.api_key:
            return normalize_results(self.provider_name, query, [], raw={"skipped": True, "reason": "missing_pat"}, error="Censys PAT is not configured")
        if not ip:
            return normalize_results(self.provider_name, query, [], raw={"skipped": True, "reason": "invalid_target"}, error="Censys requires a public IP address")
        endpoint = f"{self.settings.endpoint.rstrip('/')}/asset/host/{ip}"
        logger.info("provider=censys action=host_lookup target_ip=%s", ip)
        try:
            response = await client.get(endpoint, headers=self._headers(), follow_redirects=False)
        except httpx.TimeoutException:
            logger.warning("Censys enrichment skipped: request timed out for ip=%s", ip)
            return normalize_results(self.provider_name, ip, [], raw={"skipped": True, "reason": "timeout"}, error="Censys request timed out")
        failures = {
            401: ("unauthorized", "Censys enrichment skipped: unauthorized PAT."),
            403: ("forbidden", "Censys enrichment skipped: forbidden for configured account."),
            404: ("not_found", "Censys enrichment skipped: host not found."),
            422: ("unprocessable_entity", "Censys enrichment skipped: request was unprocessable; an organization ID may be required."),
        }
        if response.status_code in failures:
            reason, message = failures[response.status_code]
            logger.warning("%s ip=%s", message, ip)
            return normalize_results(self.provider_name, ip, [], raw={"skipped": True, "reason": reason}, status_code=response.status_code, error=f"Censys {reason}")
        if response.status_code >= 400:
            logger.warning("Censys enrichment skipped: provider status=%s ip=%s", response.status_code, ip)
            return normalize_results(self.provider_name, ip, [], raw={"skipped": True, "reason": "provider_error"}, status_code=response.status_code, error="Censys provider error")
        try:
            payload = response.json()
        except ValueError:
            logger.warning("Censys enrichment skipped: invalid JSON response ip=%s", ip)
            return normalize_results(self.provider_name, ip, [], raw={"skipped": True, "reason": "invalid_response"}, status_code=response.status_code, error="Invalid Censys response")
        result = payload.get("result") if isinstance(payload, dict) else None
        asset = result if isinstance(result, dict) else payload if isinstance(payload, dict) else {}
        services = asset.get("services") or []
        items = [{
            "identifier": ip,
            "summary": (services[0].get("service_name") or services[0].get("name")) if services and isinstance(services[0], dict) else "Censys host intelligence retrieved",
            "vendor": "Censys",
            "raw": payload,
        }]
        logger.info("provider=censys action=host_lookup target_ip=%s status=%s result=success", ip, response.status_code)
        return normalize_results(self.provider_name, ip, items, raw=payload, status_code=response.status_code)


register_simple_provider("censys", lambda settings_: CensysProvider(settings_))
