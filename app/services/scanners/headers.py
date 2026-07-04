from __future__ import annotations

import httpx

from app.config import settings
from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner


class HeaderScanner(TargetScanner):
    name = "headers"
    supported_kinds = {"url"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        findings = []
        async with httpx.AsyncClient(timeout=settings.INTELLIGENCE_REQUEST_TIMEOUT_SECONDS, follow_redirects=True, verify=settings.VERIFY_SCAN_TARGETS) as client:
            response = await client.get(target.value)
        header_map = {key.lower(): value for key, value in response.headers.items()}
        for header, finding_type, title, severity in [
            ("content-security-policy", "header", "Missing Content Security Policy", "Low"),
            ("x-frame-options", "header", "Missing X-Frame-Options", "Low"),
            ("x-content-type-options", "header", "Missing X-Content-Type-Options", "Low"),
            ("referrer-policy", "header", "Missing Referrer-Policy", "Low"),
            ("permissions-policy", "header", "Missing Permissions-Policy", "Low"),
        ]:
            if header not in header_map:
                findings.append(self._finding(
                    finding_type=finding_type,
                    title=title,
                    description=f"{title} on {target.value}",
                    severity=severity,
                    evidence={"header": header},
                    location=target.value,
                    confidence=0.86,
                    raw_data={"status_code": response.status_code, "headers": dict(response.headers)},
                    target=target.value,
                    tags=["headers", "web"],
                ))
        return ScannerResult(findings=findings, metadata={"status_code": response.status_code})