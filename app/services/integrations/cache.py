from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from redis.asyncio import Redis

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


class IntegrationCache:
    def __init__(self, *, default_ttl: int | None = None) -> None:
        self.default_ttl = default_ttl or settings.INTELLIGENCE_CACHE_TTL_SECONDS
        self._redis: Redis | None = None
        self._fallback: dict[str, str] = {}
        self._checked = False
        self._max_fallback_entries = 2000

    async def _client(self) -> Redis | None:
        if self._checked:
            return self._redis

        self._checked = True
        try:
            self._redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
            await self._redis.ping()
            logger.info("Integration cache connected to Redis")
        except Exception as exc:  # pragma: no cover - Redis may be unavailable in tests
            logger.warning("Integration cache using fallback store: %s", exc)
            self._redis = None
        return self._redis

    def build_key(self, namespace: str, *parts: str, **params: Any) -> str:
        normalized_parts = [self._normalize(part) for part in parts if part is not None]
        normalized_params = [f"{key}={self._normalize(value)}" for key, value in sorted(params.items()) if value is not None]
        suffix = ":".join([*normalized_parts, *normalized_params])
        return f"vulnexus:{namespace}:{suffix}" if suffix else f"vulnexus:{namespace}"

    async def get_json(self, key: str) -> Any | None:
        client = await self._client()
        if client is not None:
            try:
                value = await client.get(key)
                if value is not None:
                    return json.loads(value)
            except Exception as exc:  # pragma: no cover - Redis failures should not break scans
                logger.debug("Redis cache read failed for %s: %s", key, exc)
        value = self._fallback.get(key)
        return json.loads(value) if value is not None else None

    async def set_json(self, key: str, value: Any, *, ttl: int | None = None) -> None:
        serialized = json.dumps(value, default=str)
        client = await self._client()
        if client is not None:
            try:
                await client.set(key, serialized, ex=ttl or self.default_ttl)
                return
            except Exception as exc:  # pragma: no cover - Redis failures should not break scans
                logger.debug("Redis cache write failed for %s: %s", key, exc)

        if len(self._fallback) >= self._max_fallback_entries:
            self._fallback.pop(next(iter(self._fallback)))
        self._fallback[key] = serialized

    async def delete(self, *keys: str) -> None:
        client = await self._client()
        if client is not None:
            try:
                await client.delete(*keys)
            except Exception as exc:  # pragma: no cover - Redis failures should not break scans
                logger.debug("Redis cache delete failed: %s", exc)
        for key in keys:
            self._fallback.pop(key, None)

    async def clear_namespace(self, namespace: str) -> None:
        prefix = f"vulnexus:{namespace}:"
        client = await self._client()
        if client is not None:
            try:
                async for key in client.scan_iter(match=f"{prefix}*"):
                    await client.delete(key)
            except Exception as exc:  # pragma: no cover
                logger.debug("Redis cache namespace clear failed: %s", exc)
        for key in list(self._fallback):
            if key.startswith(prefix):
                self._fallback.pop(key, None)

    async def close(self) -> None:
        """Release Redis connections before the Celery task event loop closes."""
        client, self._redis = self._redis, None
        self._checked = False
        if client is not None:
            await client.aclose()

    def _normalize(self, value: Any) -> str:
        if isinstance(value, str):
            return value.strip().lower().replace(" ", "-")
        if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, dict)):
            return ",".join(self._normalize(item) for item in value)
        return str(value).strip().lower().replace(" ", "-")


cache = IntegrationCache()
