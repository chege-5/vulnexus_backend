from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.http_client import create_async_client
from app.config import settings
from app.services.integrations.cache import cache
from app.services.models.pipeline import IntelligenceResult, ProviderResponse
from app.utils.redaction import redact_text


@dataclass(slots=True)
class ProviderSettings:
    name: str
    enabled: bool = True
    api_key: str | None = None
    endpoint: str | None = None
    timeout_seconds: int = settings.INTELLIGENCE_REQUEST_TIMEOUT_SECONDS
    retry_attempts: int = settings.INTELLIGENCE_RETRY_ATTEMPTS
    retry_backoff_seconds: float = settings.INTELLIGENCE_RETRY_BACKOFF_SECONDS
    cache_ttl_seconds: int = settings.INTELLIGENCE_CACHE_TTL_SECONDS
    extra: dict[str, Any] = field(default_factory=dict)


class ProviderAdapter(ABC):
    provider_name: str

    def __init__(self, settings: ProviderSettings) -> None:
        self.settings = settings

    @property
    def enabled(self) -> bool:
        return bool(self.settings.enabled)

    @property
    def cache_namespace(self) -> str:
        return f"provider:{self.provider_name.lower()}"

    @abstractmethod
    async def lookup(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5) -> ProviderResponse:
        raise NotImplementedError

    async def health_check(self, client: httpx.AsyncClient) -> dict[str, Any]:
        return {
            "provider": self.provider_name,
            "enabled": self.enabled,
            "healthy": self.enabled,
            "endpoint": self.settings.endpoint,
        }

    async def cached_lookup(self, query: str, *, context: dict[str, Any] | None = None, limit: int = 5) -> ProviderResponse:
        key = cache.build_key(self.cache_namespace, query, limit=limit, **(context or {}))
        cached = await cache.get_json(key)
        if cached is not None:
            return ProviderResponse(
                provider=self.provider_name,
                query=query,
                cached=True,
                success=True,
                enabled=self.enabled,
                normalized=list(cached.get("normalized") or []),
                raw=dict(cached.get("raw") or {}),
                status_code=cached.get("status_code"),
                ttl_seconds=cached.get("ttl_seconds"),
                error=cached.get("error"),
            )

        timeout = httpx.Timeout(self.settings.timeout_seconds)
        headers = {"User-Agent": "Vulnexus/1.0"}
        if self.settings.api_key:
            headers.update(self._auth_headers())
        async with create_async_client(timeout=timeout, headers=headers) as client:
            response = await self._with_retry(client, query, context=context, limit=limit)
        if response.success:
            await cache.set_json(
                key,
                {
                    "normalized": response.normalized,
                    "raw": response.raw,
                    "status_code": response.status_code,
                    "ttl_seconds": response.ttl_seconds,
                    "error": response.error,
                },
                ttl=self.settings.cache_ttl_seconds,
            )
        return response

    async def _with_retry(self, client: httpx.AsyncClient, query: str, *, context: dict[str, Any] | None = None, limit: int = 5) -> ProviderResponse:
        last_error: Exception | None = None
        for attempt in range(max(1, self.settings.retry_attempts)):
            try:
                return await self.lookup(client, query, context=context, limit=limit)
            except Exception as exc:  # pragma: no cover - provider failures are environment dependent
                last_error = exc
                if attempt + 1 < self.settings.retry_attempts:
                    await self._sleep_backoff(attempt)
        return ProviderResponse(
            provider=self.provider_name,
            query=query,
            enabled=self.enabled,
            success=False,
            error=redact_text(last_error) if last_error else "Provider lookup failed",
        )

    async def _sleep_backoff(self, attempt: int) -> None:
        import asyncio

        delay = self.settings.retry_backoff_seconds * (2**attempt)
        await asyncio.sleep(delay)

    def _auth_headers(self) -> dict[str, str]:
        return {}


def normalize_results(provider: str, query: str, items: list[dict[str, Any]], *, raw: dict[str, Any] | None = None, status_code: int | None = None, error: str | None = None) -> ProviderResponse:
    return ProviderResponse(
        provider=provider,
        query=query,
        success=error is None,
        enabled=True,
        status_code=status_code,
        normalized=items,
        raw=raw or {},
        error=error,
    )


def to_intelligence_result(provider_response: ProviderResponse, *, query: str) -> IntelligenceResult:
    first = provider_response.normalized[0] if provider_response.normalized else {}
    return IntelligenceResult(
        provider=provider_response.provider,
        query=query,
        success=provider_response.success,
        cached=provider_response.cached,
        summary=first.get("summary"),
        identifier=first.get("identifier"),
        cve_id=first.get("cve_id"),
        cvss_score=first.get("cvss_score"),
        epss_score=first.get("epss_score"),
        kev=first.get("kev"),
        vendor=first.get("vendor"),
        references=list(first.get("references") or []),
        exploitability=first.get("exploitability"),
        raw=provider_response.raw,
    )
