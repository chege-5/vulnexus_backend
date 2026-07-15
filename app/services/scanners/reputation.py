from __future__ import annotations

from app.config import settings
from app.services.integrations.base import to_intelligence_result
from app.services.integrations.manager import integration_manager
from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner
from app.services.targets import InvalidTargetError, normalize_target, provider_domain


class ReputationScanner(TargetScanner):
    name = "reputation"
    supported_kinds = {"url", "domain", "ip"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        try:
            normalized = await normalize_target(target.value)
        except InvalidTargetError as exc:
            return ScannerResult(metadata={"error": str(exc), "skipped": True})
        if not settings.ENABLE_LIVE_INTELLIGENCE:
            return ScannerResult(metadata={"skipped": True, "reason": "live intelligence disabled", "public_ips": normalized.public_ips})

        responses = []
        responses.extend(await integration_manager.lookup(
            normalized.normalized_url,
            providers=["virustotal", "safebrowsing"],
            limit=5,
            context={"target_kind": "url"},
        ))
        domain = provider_domain(normalized)
        responses.extend(await integration_manager.lookup(
            domain,
            providers=["virustotal", "urlscan", "builtwith", "wappalyzer"],
            limit=5,
            context={"target_kind": "domain"},
        ))
        for ip_address in normalized.public_ips:
            responses.extend(await integration_manager.lookup(
                ip_address,
                providers=["shodan", "censys", "abuseipdb", "greynoise", "ipinfo", "virustotal"],
                limit=5,
                context={"target_kind": "public_ip"},
            ))
        intelligence = [to_intelligence_result(response, query=response.query) for response in responses if response.success or response.cached]
        provider_statuses = []
        seen_statuses = set()
        for response in responses:
            if response.success:
                continue
            status_item = {
                "provider": response.provider,
                "status": "skipped",
                "success": False,
                "status_code": response.status_code,
                "reason": response.raw.get("reason") if isinstance(response.raw, dict) else None,
                "message": response.raw.get("message", response.error) if isinstance(response.raw, dict) else response.error,
            }
            status_key = (
                status_item["provider"],
                response.query,
                status_item["status_code"],
                status_item["reason"],
                status_item["message"],
            )
            if status_key in seen_statuses:
                continue
            seen_statuses.add(status_key)
            provider_statuses.append(status_item)
        findings = []
        for response, item in zip([response for response in responses if response.success or response.cached], intelligence):
            first = response.normalized[0] if response.normalized else {}
            classification = str(first.get("classification") or "").lower()
            if item.provider == "VIRUSTOTAL" and classification == "no known detection":
                continue
            if not item.summary and not item.raw:
                continue
            severity = "High" if classification == "malicious classification" else "Medium"
            findings.append(self._finding(
                finding_type="reputation",
                title=f"{item.provider} reputation signal",
                description=item.summary or f"Reputation intelligence from {item.provider}",
                severity=severity,
                evidence={**item.model_dump(), "classification": first.get("classification"), "signal_type": first.get("signal_type")},
                location=item.query,
                confidence=0.75,
                raw_data={**item.model_dump(), "provider_item": first},
                target=target.value,
                tags=["reputation", item.provider.lower()],
            ))
        return ScannerResult(findings=findings, metadata={"public_ips": normalized.public_ips, "provider_statuses": provider_statuses})
