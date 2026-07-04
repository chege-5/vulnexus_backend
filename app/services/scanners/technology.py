from __future__ import annotations

from urllib.parse import urlparse

import httpx

from app.config import settings
from app.services.integrations.manager import integration_manager
from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner


class TechnologyFingerprintScanner(TargetScanner):
    name = "technology"
    supported_kinds = {"url"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        parsed = urlparse(target.value)
        hostname = parsed.hostname or target.value
        findings = []

        async with httpx.AsyncClient(timeout=settings.INTELLIGENCE_REQUEST_TIMEOUT_SECONDS, follow_redirects=True, verify=settings.VERIFY_SCAN_TARGETS) as client:
            response = await client.get(target.value)
        server_header = response.headers.get("server")
        powered_by = response.headers.get("x-powered-by")
        if server_header or powered_by:
            findings.append(self._finding(
                finding_type="technology",
                title="Technology fingerprint discovered",
                description=f"Detected server fingerprint for {hostname}",
                severity="Info",
                evidence={"server": server_header, "x-powered-by": powered_by},
                location=hostname,
                confidence=0.74,
                raw_data={"headers": dict(response.headers)},
                target=target.value,
                tags=["fingerprint", "technology"],
            ))

        intelligence = await integration_manager.enrich_intelligence(hostname, providers=["builtwith", "wappalyzer", "urlscan"], limit=3)
        for item in intelligence:
            findings.append(self._finding(
                finding_type="technology",
                title=f"{item.provider} technology intelligence",
                description=item.summary or f"Technology intelligence from {item.provider}",
                severity="Info",
                evidence=item.model_dump(),
                location=hostname,
                confidence=0.8,
                raw_data=item.model_dump(),
                target=target.value,
                tags=["fingerprint", item.provider.lower()],
            ))

        return ScannerResult(findings=findings, metadata={"status_code": response.status_code})