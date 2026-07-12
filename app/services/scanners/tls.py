from __future__ import annotations

import asyncio
from dataclasses import asdict
from urllib.parse import urlparse

from app.config import settings
from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner
from app.utils.tls_utils import TLS_VERSION_ORDER, TLSAssessment, assess_tls_security


class TLSScanner(TargetScanner):
    name = "tls"
    supported_kinds = {"url"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        parsed = urlparse(target.value)
        if not parsed.hostname:
            return ScannerResult(metadata={"error": "URL target did not include a hostname."})

        port = parsed.port or 443
        timeout = float(context.options.get("tls_timeout") or settings.TLS_CONNECT_TIMEOUT_SECONDS)
        assessment = await asyncio.to_thread(assess_tls_security, parsed.hostname, port, timeout, True)
        findings = self._build_findings(assessment, target.value)
        return ScannerResult(findings=findings, metadata={"tls_assessment": asdict(assessment)})

    def _build_findings(self, assessment: TLSAssessment, target_value: str):
        findings = []
        metadata = asdict(assessment)
        supported_versions = assessment.supported_protocols
        min_version = settings.TLS_MIN_VERSION
        required_version = settings.TLS_REQUIRE_VERSION

        deprecated = [version for version in supported_versions if 0 < TLS_VERSION_ORDER.get(version, 0) < TLS_VERSION_ORDER[min_version]]
        if deprecated:
            findings.append(self._finding(
                finding_type="tls_protocol",
                title="Deprecated TLS protocol version supported",
                description=f"{assessment.host}:{assessment.port} accepts deprecated TLS versions: {', '.join(deprecated)}.",
                severity="High",
                evidence={"supported_protocols": supported_versions, "deprecated_protocols": deprecated, "minimum_allowed": min_version},
                location=target_value,
                confidence=0.96,
                raw_data={"rule_id": "WEAK_TLS_VERSION", **metadata},
                target=target_value,
                tags=["tls", "protocol", "cryptography"],
            ))

        if required_version and required_version not in supported_versions:
            findings.append(self._finding(
                finding_type="tls_protocol",
                title=f"{required_version} is not supported",
                description=f"{assessment.host}:{assessment.port} did not negotiate {required_version} during active protocol probing.",
                severity="Medium",
                evidence={"supported_protocols": supported_versions, "missing_protocol": required_version},
                location=target_value,
                confidence=0.86,
                raw_data={"rule_id": "MISSING_MODERN_TLS", **metadata},
                target=target_value,
                tags=["tls", "protocol", "hardening"],
            ))

        weak_ciphers = [cipher for cipher in assessment.ciphers if cipher.classification in {"weak", "insecure"}]
        if weak_ciphers:
            findings.append(self._finding(
                finding_type="tls_cipher",
                title="Weak TLS cipher suites accepted",
                description=f"{assessment.host}:{assessment.port} accepts cipher suites classified as weak or insecure.",
                severity="High" if any(item.classification == "insecure" for item in weak_ciphers) else "Medium",
                evidence={"weak_ciphers": [asdict(item) for item in weak_ciphers], "accepted_cipher_count": len(assessment.ciphers)},
                location=target_value,
                confidence=0.9,
                raw_data={"rule_id": "WEAK_CIPHER_SUITE", **metadata},
                target=target_value,
                tags=["tls", "cipher", "cryptography"],
            ))

        if settings.TLS_REQUIRE_FORWARD_SECRECY and assessment.ciphers and not any(cipher.forward_secrecy for cipher in assessment.ciphers):
            findings.append(self._finding(
                finding_type="tls_cipher",
                title="Forward secrecy is not supported by accepted TLS 1.2 cipher suites",
                description=f"{assessment.host}:{assessment.port} accepted cipher suites, but none provided ECDHE/DHE forward secrecy.",
                severity="Medium",
                evidence={"accepted_ciphers": [cipher.name for cipher in assessment.ciphers], "forward_secrecy": False},
                location=target_value,
                confidence=0.88,
                raw_data={"rule_id": "NO_FORWARD_SECRECY", **metadata},
                target=target_value,
                tags=["tls", "cipher", "pfs"],
            ))

        cert = assessment.certificate
        if cert.expired:
            findings.append(self._finding(
                finding_type="certificate",
                title="Expired TLS certificate",
                description=f"The certificate for {assessment.host} expired on {cert.not_after}.",
                severity="Critical",
                evidence={"not_after": cert.not_after.isoformat() if cert.not_after else None, "valid_days": cert.valid_days},
                location=target_value,
                confidence=0.99,
                raw_data={"rule_id": "EXPIRED_CERT", **metadata},
                target=target_value,
                tags=["tls", "certificate", "pki"],
            ))
        elif cert.near_expiry:
            findings.append(self._finding(
                finding_type="certificate",
                title="TLS certificate expires soon",
                description=f"The certificate for {assessment.host} expires in {cert.valid_days} days.",
                severity="Low",
                evidence={"not_after": cert.not_after.isoformat() if cert.not_after else None, "valid_days": cert.valid_days, "threshold_days": settings.TLS_NEAR_EXPIRY_DAYS},
                location=target_value,
                confidence=0.96,
                raw_data={"rule_id": "CERT_NEAR_EXPIRY", **metadata},
                target=target_value,
                tags=["tls", "certificate", "lifecycle"],
            ))

        if cert.self_signed:
            findings.append(self._finding(
                finding_type="certificate",
                title="Self-signed TLS certificate",
                description=f"The certificate subject and issuer are identical for {assessment.host}.",
                severity="High",
                evidence={"subject": cert.subject, "issuer": cert.issuer},
                location=target_value,
                confidence=0.97,
                raw_data={"rule_id": "SELF_SIGNED_CERT", **metadata},
                target=target_value,
                tags=["tls", "certificate", "pki"],
            ))

        if cert.hostname_matches is False:
            findings.append(self._finding(
                finding_type="certificate",
                title="TLS certificate hostname mismatch",
                description=f"The certificate SAN/CN does not match {assessment.host}.",
                severity="High",
                evidence={"hostname": assessment.host, "san_dns_names": cert.san_dns_names, "subject": cert.subject},
                location=target_value,
                confidence=0.94,
                raw_data={"rule_id": "CERT_HOSTNAME_MISMATCH", **metadata},
                target=target_value,
                tags=["tls", "certificate", "pki"],
            ))

        if cert.weak_signature_algorithm or cert.weak_key:
            findings.append(self._finding(
                finding_type="certificate",
                title="Weak TLS certificate cryptography",
                description=f"The certificate uses weak cryptographic properties: signature={cert.signature_algorithm}, key={cert.public_key_algorithm} {cert.public_key_bits}.",
                severity="High",
                evidence={"signature_algorithm": cert.signature_algorithm, "public_key_algorithm": cert.public_key_algorithm, "public_key_bits": cert.public_key_bits, "weak_signature": cert.weak_signature_algorithm, "weak_key": cert.weak_key},
                location=target_value,
                confidence=0.95,
                raw_data={"rule_id": "WEAK_CERT_CRYPTO", **metadata},
                target=target_value,
                tags=["tls", "certificate", "cryptography"],
            ))

        if cert.chain_trusted is False:
            findings.append(self._finding(
                finding_type="certificate",
                title="TLS certificate chain is not trusted",
                description=f"Certificate trust validation failed for {assessment.host}.",
                severity="High",
                evidence={"chain_trusted": False, "validation_error": cert.validation_error},
                location=target_value,
                confidence=0.93,
                raw_data={"rule_id": "UNTRUSTED_CERT_CHAIN", **metadata},
                target=target_value,
                tags=["tls", "certificate", "pki"],
            ))

        hsts = assessment.hsts
        if hsts.present is False:
            findings.append(self._finding(
                finding_type="transport_header",
                title="HSTS is not enabled",
                description=f"{assessment.host} did not return a Strict-Transport-Security header over HTTPS.",
                severity="Low",
                evidence={"header": "Strict-Transport-Security", "present": False},
                location=target_value,
                confidence=0.88,
                raw_data={"rule_id": "NO_HSTS", **metadata},
                target=target_value,
                tags=["headers", "tls", "transport"],
            ))
        elif hsts.weak:
            findings.append(self._finding(
                finding_type="transport_header",
                title="HSTS max-age is below policy",
                description=f"{assessment.host} has HSTS, but max-age is below {settings.TLS_HSTS_MIN_AGE_SECONDS} seconds.",
                severity="Low",
                evidence={"raw_header": hsts.raw_header, "max_age": hsts.max_age, "minimum_max_age": settings.TLS_HSTS_MIN_AGE_SECONDS, "include_subdomains": hsts.include_subdomains},
                location=target_value,
                confidence=0.9,
                raw_data={"rule_id": "WEAK_HSTS", **metadata},
                target=target_value,
                tags=["headers", "tls", "transport"],
            ))

        if assessment.errors:
            findings.append(self._finding(
                finding_type="tls_scan_status",
                title="TLS assessment was incomplete",
                description=f"TLS assessment for {assessment.host}:{assessment.port} completed with limitations.",
                severity="Info",
                evidence={"errors": assessment.errors, "limitations": assessment.limitations},
                location=target_value,
                confidence=1.0,
                raw_data={"rule_id": "TLS_SCAN_INCOMPLETE", **metadata},
                target=target_value,
                tags=["tls", "scanner-status"],
            ))

        return findings
