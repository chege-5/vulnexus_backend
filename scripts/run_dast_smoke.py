"""Controlled, public-host smoke checks for the process-backed DAST enrichments."""
from __future__ import annotations

import asyncio
from uuid import uuid4

from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.crtsh import CrtShScanner
from app.services.scanners.sslyze import SSLyzeScanner


async def main() -> None:
    target = ScanTarget(kind="url", value="https://example.com")
    context = ScanContext(scan_id=uuid4(), scan_type="url", target=target)
    sslyze, crtsh = await asyncio.gather(SSLyzeScanner().scan(target, context), CrtShScanner().scan(target, context))

    def summary(result):
        return {
            "findings": len(result.findings),
            "provider_statuses": (result.metadata or {}).get("provider_statuses") or [],
        }

    print({"sslyze": summary(sslyze), "crtsh": summary(crtsh)})


if __name__ == "__main__":
    asyncio.run(main())
