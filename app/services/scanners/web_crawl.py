from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from app.config import settings
from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner


class WebCrawlScanner(TargetScanner):
    name = "web_crawl"
    supported_kinds = {"url"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        async with httpx.AsyncClient(timeout=settings.INTELLIGENCE_REQUEST_TIMEOUT_SECONDS, follow_redirects=True, verify=settings.VERIFY_SCAN_TARGETS) as client:
            response = await client.get(target.value)
        links = set(re.findall(r'href=["\']([^"\']+)', response.text, flags=re.IGNORECASE))
        discovered = []
        for link in sorted(links):
            absolute = urljoin(target.value, link)
            if absolute.startswith(target.value.split("#")[0].rstrip("/")):
                discovered.append(absolute)
        if not discovered:
            return ScannerResult(metadata={"endpoints": 0})
        return ScannerResult(findings=[self._finding(
            finding_type="endpoint",
            title="Discovered application endpoints",
            description=f"Discovered {len(discovered)} internal endpoints on {target.value}",
            severity="Info",
            evidence={"endpoints": discovered[:25]},
            location=target.value,
            confidence=0.7,
            raw_data={"endpoints": discovered},
            target=target.value,
            tags=["crawl", "endpoint-discovery"],
        )], metadata={"endpoints": discovered})