from __future__ import annotations

import socket
from urllib.parse import urlparse

from app.services.integrations.manager import integration_manager
from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner


class ReputationScanner(TargetScanner):
    name = "reputation"
    supported_kinds = {"url", "domain", "ip"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        hostname = target.value
        if target.kind == "url":
            parsed = urlparse(target.value)
            hostname = parsed.hostname or target.value

        ip_address = hostname
        try:
            if not self._looks_like_ip(hostname):
                ip_address = socket.gethostbyname(hostname)
        except Exception:
            ip_address = hostname

        intelligence = await integration_manager.enrich_intelligence(ip_address, providers=["shodan", "censys", "abuseipdb", "greynoise", "ipinfo"], limit=5, context={"hostname": hostname})
        findings = []
        for item in intelligence:
            if not item.summary and not item.raw:
                continue
            findings.append(self._finding(
                finding_type="reputation",
                title=f"{item.provider} reputation signal",
                description=item.summary or f"Reputation intelligence from {item.provider}",
                severity="Medium",
                evidence=item.model_dump(),
                location=ip_address,
                confidence=0.75,
                raw_data=item.model_dump(),
                target=target.value,
                tags=["reputation", item.provider.lower()],
            ))
        return ScannerResult(findings=findings, metadata={"ip_address": ip_address})

    def _looks_like_ip(self, value: str) -> bool:
        return value.count(".") == 3 or ":" in value