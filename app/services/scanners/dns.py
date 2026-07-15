from __future__ import annotations

import asyncio
import socket
from urllib.parse import urlparse

from app.config import settings
from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner


class DNSScanner(TargetScanner):
    name = "dns"
    supported_kinds = {"url", "domain", "ip"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        hostname = target.value
        if target.kind == "url":
            parsed = urlparse(target.value)
            hostname = parsed.hostname or target.value

        try:
            await asyncio.wait_for(
                asyncio.to_thread(socket.gethostbyname_ex, hostname),
                timeout=settings.INTELLIGENCE_REQUEST_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            return ScannerResult(findings=[self._finding(
                finding_type="dns",
                title="DNS resolution failed",
                description=f"Unable to resolve {hostname}",
                severity="Medium",
                evidence={"error": str(exc)},
                location=hostname,
                confidence=0.9,
                raw_data={"exception": str(exc)},
                target=target.value,
                tags=["dns"],
            )], metadata={"resolved": False})

        return ScannerResult(metadata={"resolved": True})
