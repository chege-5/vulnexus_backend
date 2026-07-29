"""Certificate Transparency intelligence from crt.sh for admitted URL targets."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.services.models.pipeline import RawFinding, ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner
from app.utils.logger import get_logger
from app.utils.redaction import redact_data, redact_text

logger = get_logger(__name__)

_SENSITIVE_LABELS = {"admin", "api", "dev", "internal", "jira", "mail", "portal", "prod", "staging", "test", "uat", "vpn"}


class CrtShScanner(TargetScanner):
    name = "crtsh"
    supported_kinds = {"url"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        if not settings.CRTSH_ENABLED:
            return ScannerResult(metadata={"provider_statuses": [self._status("disabled")]})
        hostname = urlparse(target.value).hostname
        if not hostname:
            return ScannerResult(metadata={"provider_statuses": [self._status("skipped", reason="missing_hostname")]})
        timeout_value = float(settings.CRTSH_TIMEOUT_SECONDS)
        timeout = httpx.Timeout(timeout_value, connect=min(5.0, timeout_value), read=timeout_value, write=min(5.0, timeout_value), pool=min(5.0, timeout_value))
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                response = await asyncio_wait_for(client.get(settings.CRTSH_API_URL, params={"q": f"%.{hostname}", "output": "json"}), timeout_value)
            if response.status_code != 200:
                return ScannerResult(metadata={"provider_statuses": [self._status("skipped", reason="http_error", status_code=response.status_code)]})
            payload = response.json()
        except (httpx.HTTPError, ValueError, TimeoutError) as exc:
            category = self._error_category(exc)
            # Keep a useful diagnostic without logging response bodies, URLs
            # containing credentials, or raw exception text.
            logger.warning(
                "crt.sh enrichment failed host=%s error=%s exception_class=%s",
                hostname,
                category,
                type(exc).__name__,
            )
            return ScannerResult(metadata={"provider_statuses": [self._status("skipped", reason=category, error=category, exception_class=type(exc).__name__)]})

        intelligence = self._normalize(payload, hostname)
        findings = self._build_findings(intelligence, target.value)
        metadata = {
            "provider": "crtsh",
            "certificate_count": intelligence["certificate_count"],
            "matching_name_count": intelligence["matching_name_count"],
            "provider_statuses": [self._status("success", certificate_count=intelligence["certificate_count"])],
        }
        return ScannerResult(findings=findings, metadata=redact_data(metadata))

    def _normalize(self, payload: Any, hostname: str) -> dict[str, Any]:
        rows = payload if isinstance(payload, list) else []
        names: set[str] = set()
        certificates: set[tuple[str, str]] = set()
        for row in rows[: settings.CRTSH_MAX_RESULTS]:
            if not isinstance(row, dict):
                continue
            certificate_id = str(row.get("id") or row.get("serial_number") or "")
            issuer_id = str(row.get("issuer_ca_id") or "")
            if certificate_id:
                certificates.add((certificate_id, issuer_id))
            for name in str(row.get("name_value") or "").splitlines():
                normalized = name.strip().lower().lstrip("*.")
                if normalized == hostname or normalized.endswith("." + hostname):
                    names.add(normalized)
        sensitive = sorted(name for name in names if any(label in _SENSITIVE_LABELS for label in name.split(".")[:-2]))
        return {
            "certificate_count": len(certificates),
            "matching_name_count": len(names),
            "sample_names": [self._redact_name(name) for name in sorted(names)[:5]],
            "sensitive_names": [self._redact_name(name) for name in sensitive[:5]],
        }

    def _build_findings(self, intelligence: dict[str, Any], target_value: str) -> list[RawFinding]:
        if not intelligence["certificate_count"]:
            return []
        findings = [self._finding(
            finding_type="certificate_transparency",
            title="Certificate Transparency inventory discovered",
            description="crt.sh contains certificate records for the admitted hostname and its matching names.",
            severity="Info",
            evidence=redact_data({"source": "crt.sh", "category": "Certificate Transparency intelligence", "certificate_count": intelligence["certificate_count"], "matching_name_count": intelligence["matching_name_count"], "sample_names": intelligence["sample_names"]}),
            location=target_value,
            confidence=0.98,
            confidence_label="confirmed",
            raw_data={"rule_id": "DAST_CRTSH_CERTIFICATE_INVENTORY", "source_metadata": {"provider": "crt.sh", "raw_response_omitted": True}},
            target=target_value,
            tags=["dast", "certificate-transparency", "crtsh"],
            remediation="Maintain an inventory of publicly issued certificates and decommission or restrict unintended hostnames.",
            references=["https://crt.sh/"],
        )]
        if intelligence["sensitive_names"]:
            findings.append(self._finding(
                finding_type="certificate_transparency",
                title="Potentially sensitive hostnames exposed through Certificate Transparency",
                description="Certificate Transparency records include names that merit asset-inventory and exposure review.",
                severity="Medium",
                evidence=redact_data({"source": "crt.sh", "category": "Certificate Transparency intelligence", "sensitive_name_count": len(intelligence["sensitive_names"]), "sample_names": intelligence["sensitive_names"]}),
                location=target_value,
                confidence=0.78,
                confidence_label="probable",
                raw_data={"rule_id": "DAST_CRTSH_SENSITIVE_SUBDOMAIN", "source_metadata": {"provider": "crt.sh", "raw_response_omitted": True}},
                target=target_value,
                tags=["dast", "certificate-transparency", "asset-inventory", "crtsh"],
                remediation="Confirm each discovered hostname is intended, access-controlled, and covered by asset management; retire stale DNS and certificates.",
                references=["https://crt.sh/"],
            ))
        return findings

    @staticmethod
    def _redact_name(name: str) -> str:
        labels = name.split(".")
        if len(labels) >= 2:
            return "[REDACTED-SUBDOMAIN]." + ".".join(labels[-2:])
        return "[REDACTED-HOST]"

    @staticmethod
    def _status(status: str, **details: Any) -> dict[str, Any]:
        return {"provider": "crtsh", "status": status, "success": status == "success", **details}

    @staticmethod
    def _error_category(exc: Exception) -> str:
        if isinstance(exc, (TimeoutError, httpx.TimeoutException)):
            return "timeout"
        if isinstance(exc, ValueError):
            return "invalid_response"
        if isinstance(exc, httpx.HTTPError):
            return "request_error"
        return "provider_error"


async def asyncio_wait_for(awaitable, timeout: float):
    """Keep an explicit overall deadline in addition to httpx phase timeouts."""
    import asyncio
    return await asyncio.wait_for(awaitable, timeout=timeout)
