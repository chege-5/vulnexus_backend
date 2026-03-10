import json
from typing import Optional
from app.utils.logger import get_logger

logger = get_logger(__name__)

_redis_client = None
_redis_checked = False


async def _get_redis():
    global _redis_client, _redis_checked
    if not _redis_checked:
        _redis_checked = True
        try:
            from redis.asyncio import Redis
            from app.config import settings
            _redis_client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
            await _redis_client.ping()
            logger.info("Redis cache connected")
        except Exception as e:
            logger.warning(f"Redis unavailable, falling back to in-memory cache: {e}")
            _redis_client = None
    return _redis_client


class RedisCache:
    def __init__(self, ttl: int = 3600):
        self._ttl = ttl
        self._fallback: dict[str, str] = {}
        self._max_fallback = 1000

    async def get(self, prefix: str, identifier: str) -> Optional[dict]:
        key = f"vulnexus:{prefix}:{identifier}"
        client = await _get_redis()
        if client:
            try:
                val = await client.get(key)
                if val:
                    return json.loads(val)
                return None
            except Exception:
                pass
        val = self._fallback.get(key)
        return json.loads(val) if val else None

    async def set(self, prefix: str, identifier: str, data: dict):
        key = f"vulnexus:{prefix}:{identifier}"
        serialized = json.dumps(data, default=str)
        client = await _get_redis()
        if client:
            try:
                await client.set(key, serialized, ex=self._ttl)
                return
            except Exception:
                pass
        if len(self._fallback) >= self._max_fallback:
            oldest_key = next(iter(self._fallback))
            del self._fallback[oldest_key]
        self._fallback[key] = serialized

    async def clear(self):
        client = await _get_redis()
        if client:
            try:
                async for key in client.scan_iter("vulnexus:*"):
                    await client.delete(key)
            except Exception:
                pass
        self._fallback.clear()


cache = RedisCache()
