from __future__ import annotations

from typing import Any

import httpx

from app.services.integrations.base import normalize_results
from app.services.integrations.providers.common import SimpleJsonProvider, register_simple_provider
from app.services.integrations.providers.target_validation import public_ip_or_none
from app.utils.logger import get_logger

logger = get_logger(__name__)


PLAN_RESTRICTED_MESSAGE = "Shodan request reached API but no usable data was returned due to account/plan restrictions."


class ShodanProvider(SimpleJsonProvider):
    provider_name = "SHODAN"

    def _auth_headers(self) -> dict[str, str]:
        return {}

    def _skipped(self, query: str, *, reason: str, error: str, status_code: int | None = None):
        return normalize_results(
            self.provider_name,
            query,
            [],
            raw={"skipped": True, "reason": reason, "message": error},
            status_code=status_code,
            error=error,
        )

    def _failure(self, status_code: int, response_text: str) -> tuple[str, str]:
        if status_code == 401:
            return "invalid_or_missing_api_key", "Shodan API key is invalid or missing."
        if status_code == 403:
            return "forbidden_or_free_plan_restricted", PLAN_RESTRICTED_MESSAGE
        if status_code == 404:
            return "no_shodan_data_for_ip", "Shodan has no indexed data for this public IP."
        lowered = response_text.lower()
        if status_code in {402, 429} or "credit" in lowered or "rate limit" in lowered or "rate-limit" in lowered:
            return "rate_or_credit_limited", "Shodan request was skipped because the account is rate or credit limited."
        return "provider_error", "Shodan request completed without usable provider data."

    async def api_info(self, client: httpx.AsyncClient):
        """Validate an API key through the free-plan-safe /api-info endpoint."""
        if not self.settings.api_key:
            return self._skipped("api-info", reason="invalid_or_missing_api_key", error="Shodan API key is invalid or missing.")
        try:
            response = await client.get(
                f"{self.settings.endpoint.rstrip('/')}/api-info",
                params={"key": self.settings.api_key},
                follow_redirects=False,
            )
        except httpx.TimeoutException:
            logger.warning("Shodan API key validation timed out")
            return self._skipped("api-info", reason="timeout", error="Shodan API key validation timed out.")
        if response.status_code != 200:
            reason, message = self._failure(response.status_code, response.text)
            logger.warning("Shodan API key validation skipped status=%s reason=%s", response.status_code, reason)
            return self._skipped("api-info", reason=reason, error=message, status_code=response.status_code)
        try:
            payload = response.json()
        except ValueError:
            return self._skipped("api-info", reason="invalid_response", error="Shodan API key validation returned an invalid response.", status_code=200)
        return normalize_results(self.provider_name, "api-info", [{"identifier": "api-info", "summary": "Shodan API key validated", "vendor": "Shodan", "raw": payload}], raw=payload, status_code=200)

    async def health_check(self, client: httpx.AsyncClient) -> dict[str, Any]:
        result = await self.api_info(client)
        return {
            "provider": self.provider_name,
            "enabled": self.enabled,
            "healthy": result.success,
            "message": "Shodan API key validated" if result.success else result.error,
            "endpoint": f"{self.settings.endpoint.rstrip('/')}/api-info",
            "status_code": result.status_code,
            "reason": result.raw.get("reason") if isinstance(result.raw, dict) else None,
        }

    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5):
        ip = public_ip_or_none(query)
        if not self.settings.api_key:
            return self._skipped(query, reason="invalid_or_missing_api_key", error="Shodan API key is invalid or missing.")
        if not ip:
            return self._skipped(query, reason="invalid_target", error="Shodan host lookup requires a resolved public IP address.")
        if not self.settings.extra.get("host_lookup_enabled", True):
            return self._skipped(ip, reason="host_lookup_disabled", error="Shodan host lookup is disabled by configuration.")

        endpoint = f"{self.settings.endpoint.rstrip('/')}/shodan/host/{ip}"
        logger.info("provider=shodan action=host_lookup target_ip=%s", ip)
        try:
            response = await client.get(endpoint, params={"key": self.settings.api_key}, follow_redirects=False)
        except httpx.TimeoutException:
            logger.warning("Shodan host lookup skipped: request timed out ip=%s", ip)
            return self._skipped(ip, reason="timeout", error="Shodan request timed out.")
        if response.status_code != 200:
            reason, message = self._failure(response.status_code, response.text)
            logger.warning("Shodan host lookup skipped status=%s reason=%s ip=%s", response.status_code, reason, ip)
            return self._skipped(ip, reason=reason, error=message, status_code=response.status_code)
        try:
            payload = response.json()
        except ValueError:
            logger.warning("Shodan host lookup skipped: invalid JSON response ip=%s", ip)
            return self._skipped(ip, reason="invalid_response", error="Shodan returned an invalid response.", status_code=200)
        items = [{
            "identifier": ip,
            "summary": payload.get("org") or payload.get("isp") or ((payload.get("data") or [{}])[0].get("product")),
            "vendor": "Shodan",
            "raw": payload,
        }]
        logger.info("provider=shodan action=host_lookup target_ip=%s status=%s result=success", ip, response.status_code)
        return normalize_results(self.provider_name, ip, items, raw=payload, status_code=response.status_code)


register_simple_provider("shodan", lambda settings_: ShodanProvider(settings_))
