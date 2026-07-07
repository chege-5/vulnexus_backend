from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner
from app.utils.tls_utils import TLSInfo, check_hsts, get_tls_info


class TLSScanner(TargetScanner):
    name = "tls"
    supported_kinds = {"url"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        parsed = urlparse(target.value)
        if not parsed.hostname:
            return ScannerResult()

        tls_info = await asyncio.to_thread(get_tls_info, parsed.hostname, parsed.port or 443)
        has_hsts = await asyncio.to_thread(check_hsts, parsed.hostname)
        findings = []

        version_map = {"TLSv1": 1.0, "TLSv1.0": 1.0, "TLSv1.1": 1.1, "TLSv1.2": 1.2, "TLSv1.3": 1.3}
        tls_version = version_map.get(tls_info.tls_version, 0)

        if 0 < tls_version < 1.2:
            findings.append(self._finding(
                finding_type="tls",
                title="Weak TLS version",
                description=f"Weak TLS version {tls_info.tls_version} detected on {target.value}",
                severity="High",
                evidence={"tls_version": tls_info.tls_version},
                location=target.value,
                confidence=0.92,
                raw_data=tls_info.__dict__,
                target=target.value,
                tags=["tls", "transport"],
            ))

        if tls_info.self_signed:
            findings.append(self._finding(
                finding_type="certificate",
                title="Self-signed certificate",
                description=f"Self-signed certificate detected on {target.value}",
                severity="High",
                evidence={"self_signed": True},
                location=target.value,
                confidence=0.97,
                raw_data=tls_info.__dict__,
                target=target.value,
                tags=["certificate", "tls"],
            ))

        if tls_info.cert_expired:
            findings.append(self._finding(
                finding_type="certificate",
                title="Expired certificate",
                description=f"Expired certificate detected on {target.value}",
                severity="Critical",
                evidence={"cert_expired": True},
                location=target.value,
                confidence=0.99,
                raw_data=tls_info.__dict__,
                target=target.value,
                tags=["certificate", "availability"],
            ))

        if not tls_info.forward_secrecy:
            findings.append(self._finding(
                finding_type="tls",
                title="Forward secrecy disabled",
                description=f"No forward secrecy detected on {target.value}",
                severity="Medium",
                evidence={"forward_secrecy": False},
                location=target.value,
                confidence=0.9,
                raw_data=tls_info.__dict__,
                target=target.value,
                tags=["tls", "transport"],
            ))

        weak_ciphers = ("RC4", "DES", "3DES", "NULL", "EXPORT", "ANON")
        if any(token in (tls_info.cipher_suite or "").upper() for token in weak_ciphers):
            findings.append(self._finding(
                finding_type="tls",
                title="Weak cipher suite",
                description=f"Weak cipher suite {tls_info.cipher_suite} detected on {target.value}",
                severity="High",
                evidence={"cipher_suite": tls_info.cipher_suite},
                location=target.value,
                confidence=0.9,
                raw_data=tls_info.__dict__,
                target=target.value,
                tags=["tls", "cipher"],
            ))

        if has_hsts is False:
            findings.append(self._finding(
                finding_type="header",
                title="Missing HSTS",
                description=f"HSTS header missing on {target.value}",
                severity="Low",
                evidence={"header": "Strict-Transport-Security"},
                location=target.value,
                confidence=0.88,
                raw_data=tls_info.__dict__,
                target=target.value,
                tags=["headers", "transport"],
            ))

        return ScannerResult(findings=findings, metadata={"tls_info": tls_info.__dict__})