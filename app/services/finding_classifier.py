from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from app.services.models.pipeline import RawFinding


class FindingClassification(StrEnum):
    CRYPTOGRAPHIC_CONFIG_WEAKNESS = "cryptographic_config_weakness"
    CERTIFICATE_TRUST_FAILURE = "certificate_trust_failure"
    PROTOCOL_SUPPORT_ISSUE = "protocol_support_issue"
    SOURCE_CRYPTO_ISSUE = "source_crypto_issue"
    SECRET_EXPOSURE = "secret_exposure"
    SOFTWARE_VULNERABILITY = "software_vulnerability"
    INFORMATIONAL_ASSET_INTELLIGENCE = "informational_asset_intelligence"
    EXTERNAL_INTELLIGENCE_FAILURE = "external_intelligence_failure"
    UNKNOWN = "unknown"


CERTIFICATE_RULES = {
    "EXPIRED_CERT",
    "SELF_SIGNED_CERT",
    "CERT_HOSTNAME_MISMATCH",
    "UNTRUSTED_CERT_CHAIN",
    "CERT_NEAR_EXPIRY",
}
PROTOCOL_RULES = {"WEAK_TLS_VERSION", "WEAK_TLS", "MISSING_MODERN_TLS"}
CRYPTO_CONFIG_RULES = {
    "WEAK_TLS_CONFIGURATION",
    "WEAK_CIPHER_SUITE",
    "NO_FORWARD_SECRECY",
    "NO_PFS",
    "WEAK_CERT_CRYPTO",
    "NO_HSTS",
    "MISSING_HSTS",
    "WEAK_HSTS",
}
SOURCE_CRYPTO_RULES = {
    "WEAK_HASH_MD5",
    "WEAK_HASH_SHA1",
    "WEAK_CIPHER_DES",
    "WEAK_CIPHER_RC2",
    "WEAK_CIPHER_AES-ECB",
    "SMALL_RSA_KEY",
    "SMALL_AES_KEY",
    "INSECURE_RANDOM",
    "STATIC_IV",
    "STATIC_SALT",
    "WEAK_KDF",
    "USES_MD5",
    "USES_SHA1",
    "USES_DES",
    "USES_RC2",
    "USES_ECB",
    "RSA_SMALL",
    "AES_SMALL",
}
SECRET_RULES = {"HARDCODED_KEY", "HARDCODED_SECRET", "SECRET_EXPOSURE"}

SOFTWARE_PRODUCTS = {
    "apache",
    "nginx",
    "openssl",
    "libressl",
    "wolfssl",
    "openssh",
    "tomcat",
    "wordpress",
    "log4j",
    "jquery",
    "django",
    "flask",
    "spring",
    "express",
    "node",
    "php",
}

VERSION_RE = re.compile(r"\b(?:v(?:ersion)?\s*)?\d+(?:\.\d+){1,4}[a-z0-9._-]*\b", re.IGNORECASE)


def classify_raw_finding(finding: RawFinding) -> FindingClassification:
    return classify_finding(
        title=finding.title,
        description=finding.description,
        finding_type=finding.type,
        source=finding.source,
        tags=finding.tags,
        evidence=finding.evidence,
        metadata=finding.raw_data,
    )


def classify_finding(
    *,
    title: str | None = None,
    description: str | None = None,
    finding_type: str | None = None,
    source: str | None = None,
    tags: list[str] | None = None,
    evidence: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> FindingClassification:
    metadata = metadata or {}
    evidence = evidence or {}
    rule_id = _normalize_rule_id(metadata.get("rule_id") or evidence.get("rule_id"))
    haystack = _haystack(title, description, finding_type, source, tags, evidence, metadata)

    if rule_id in CERTIFICATE_RULES or any(token in haystack for token in ("expired certificate", "hostname mismatch", "chain is not trusted", "self-signed", "certificate trust")):
        return FindingClassification.CERTIFICATE_TRUST_FAILURE
    if rule_id in PROTOCOL_RULES or any(token in haystack for token in ("tls 1.0", "tls 1.1", "tlsv1.3 is not supported", "tls 1.3 is not supported", "deprecated tls protocol")):
        return FindingClassification.PROTOCOL_SUPPORT_ISSUE
    if rule_id in CRYPTO_CONFIG_RULES or any(token in haystack for token in ("weak cipher", "missing hsts", "hsts is not enabled", "forward secrecy", "weak certificate signature", "weak rsa key")):
        return FindingClassification.CRYPTOGRAPHIC_CONFIG_WEAKNESS
    if rule_id in SECRET_RULES or any(token in haystack for token in ("hardcoded secret", "hardcoded key", "credential", "api token", "password")):
        return FindingClassification.SECRET_EXPOSURE
    if rule_id in SOURCE_CRYPTO_RULES or any(token in haystack for token in ("static iv", "static salt", "insecure random", "weak hash", "weak kdf")):
        return FindingClassification.SOURCE_CRYPTO_ISSUE
    if _is_external_intelligence_failure(haystack, evidence, metadata):
        return FindingClassification.EXTERNAL_INTELLIGENCE_FAILURE
    if "reputation" in haystack or any(token in haystack for token in ("shodan", "censys", "abuseipdb", "ipinfo", "greynoise", "asset intelligence")):
        return FindingClassification.INFORMATIONAL_ASSET_INTELLIGENCE
    if _has_software_vulnerability_evidence(haystack, evidence, metadata):
        return FindingClassification.SOFTWARE_VULNERABILITY
    return FindingClassification.UNKNOWN


def is_software_vulnerability_classification(classification: str | FindingClassification | None) -> bool:
    return str(classification or "") == FindingClassification.SOFTWARE_VULNERABILITY.value


def build_software_lookup_query(finding_key: str | None, metadata: dict[str, Any] | None = None) -> str:
    metadata = metadata or {}
    cve = _first(metadata, "cve_id", "cve", "advisory", "identifier")
    if cve and str(cve).upper().startswith("CVE-"):
        return str(cve).strip().upper()

    product = _first(metadata, "product", "package", "name", "component", "library")
    version = _first(metadata, "version", "detected_version")
    vendor = _first(metadata, "vendor")

    dependency = metadata.get("dependency") if isinstance(metadata.get("dependency"), dict) else {}
    if not product:
        product = _first(dependency, "package", "name")
    if not version:
        version = _first(dependency, "version")

    parts = [str(part).strip() for part in (vendor, product, version) if part]
    if parts:
        return " ".join(dict.fromkeys(parts))
    return str(finding_key or "").strip()


def safe_intelligence_context(metadata: dict[str, Any] | None) -> dict[str, Any]:
    metadata = metadata or {}
    allowed = {
        "vendor",
        "product",
        "package",
        "name",
        "component",
        "library",
        "version",
        "detected_version",
        "ecosystem",
        "cve",
        "cve_id",
        "advisory",
        "identifier",
        "classification",
    }
    safe = {key: value for key, value in metadata.items() if key in allowed and _simple_value(value)}
    dependency = metadata.get("dependency")
    if isinstance(dependency, dict):
        for key in ("package", "name", "version", "ecosystem"):
            value = dependency.get(key)
            if _simple_value(value):
                safe.setdefault(key, value)
    return safe


def _has_software_vulnerability_evidence(haystack: str, evidence: dict[str, Any], metadata: dict[str, Any]) -> bool:
    if any(str(_first(metadata, key) or "").upper().startswith("CVE-") for key in ("cve_id", "cve", "advisory")):
        return True
    if "dependency_vulnerability" in haystack or "vulnerable dependency" in haystack:
        return True
    product = _first(metadata, "product", "package", "component", "library", "name") or _first(evidence, "product", "package", "component", "library", "name")
    version = _first(metadata, "version", "detected_version") or _first(evidence, "version", "detected_version")
    if product and version:
        return True
    return any(product in haystack for product in SOFTWARE_PRODUCTS) and bool(VERSION_RE.search(haystack))


def _is_external_intelligence_failure(haystack: str, evidence: dict[str, Any], metadata: dict[str, Any]) -> bool:
    status = _first(evidence, "status_code", "status") or _first(metadata, "status_code", "status")
    error = str(_first(evidence, "error") or _first(metadata, "error") or "").lower()
    provider = any(token in haystack for token in ("shodan", "censys", "abuseipdb", "ipinfo", "greynoise", "provider"))
    auth_or_limit = status in {401, 403, 429} or any(token in error for token in ("auth", "api key", "rate limit", "forbidden", "unauthorized", "unavailable", "invalid request"))
    return provider and auth_or_limit


def _haystack(*parts: Any) -> str:
    return " ".join(str(part) for part in parts if part).lower()


def _normalize_rule_id(value: Any) -> str:
    return str(value or "").strip().upper().replace("-", "_").replace(" ", "_")


def _first(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", []):
            return value
    return None


def _simple_value(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) and len(str(value)) <= 120
