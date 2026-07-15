"""Verify Censys Platform PAT access without printing secrets or payloads."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.config import settings
from app.services.integrations.base import ProviderSettings
from app.services.integrations.providers.censys import CensysProvider


async def main() -> None:
    provider = CensysProvider(
        ProviderSettings(
            name="censys",
            api_key=settings.CENSYS_PAT,
            endpoint=settings.CENSYS_API_BASE_URL,
            timeout_seconds=settings.CENSYS_TIMEOUT_SECONDS,
            extra={"organization_id": settings.CENSYS_ORGANIZATION_ID},
        )
    )
    async with httpx.AsyncClient(timeout=settings.CENSYS_TIMEOUT_SECONDS, follow_redirects=False) as client:
        result = await provider.lookup(client, "8.8.8.8")
    print(f"censys_success={result.success} status={result.status_code} error={bool(result.error)}")


if __name__ == "__main__":
    asyncio.run(main())
