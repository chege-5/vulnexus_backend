from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.services.audit_engine import RULE_PROFILE_MAP
from app.services.finding_classifier import (
    FindingClassification,
    build_software_lookup_query,
    classify_finding,
    is_software_vulnerability_classification,
)


@dataclass(frozen=True, slots=True)
class MappingDecision:
    finding_key: str
    cwe_ids: list[str]
    owasp_category: str | None
    nist_control: str | None
    requires_cve_lookup: bool
    risk_level: str
    technical_explanation: str
    remediation: str
    references: list[str]
    classification: str


FINDING_MAP: dict[str, dict[str, Any]] = {
    "MISSING_CSP": {
        "cwe_ids": ["CWE-693"],
        "owasp_category": "A05 Security Misconfiguration",
        "nist_control": "SC-8",
        "risk_level": "Medium",
        "classification": FindingClassification.CRYPTOGRAPHIC_CONFIG_WEAKNESS.value,
        "technical_explanation": "The application does not enforce Content Security Policy, leaving it vulnerable to script injection and content trust abuse.",
        "remediation": "Deploy a restrictive Content-Security-Policy that defaults to self, then explicitly allow only trusted script, style, and connect sources.",
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy"],
    },
    "MISSING_HSTS": {
        "cwe_ids": ["CWE-319", "CWE-693"],
        "owasp_category": "A05 Security Misconfiguration",
        "nist_control": "SC-8",
        "risk_level": "Medium",
        "classification": FindingClassification.CRYPTOGRAPHIC_CONFIG_WEAKNESS.value,
        "technical_explanation": "HTTP Strict-Transport-Security is absent, so browsers can be downgraded to insecure HTTP after the first visit.",
        "remediation": "Send HSTS with a long max-age, includeSubDomains where appropriate, and preload only after validation.",
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"],
    },
    "MISSING_X_FRAME_OPTIONS": {
        "cwe_ids": ["CWE-1021"],
        "owasp_category": "A05 Security Misconfiguration",
        "nist_control": "SC-10",
        "risk_level": "Low",
        "classification": FindingClassification.CRYPTOGRAPHIC_CONFIG_WEAKNESS.value,
        "technical_explanation": "The application allows clickjacking-style framing because anti-framing controls are not present.",
        "remediation": "Set X-Frame-Options or a frame-ancestors directive in CSP to deny hostile framing.",
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"],
    },
    "MISSING_X_CONTENT_TYPE_OPTIONS": {
        "cwe_ids": ["CWE-16"],
        "owasp_category": "A05 Security Misconfiguration",
        "nist_control": "SC-8",
        "risk_level": "Low",
        "classification": FindingClassification.CRYPTOGRAPHIC_CONFIG_WEAKNESS.value,
        "technical_explanation": "The browser may MIME-sniff responses because nosniff is not enforced.",
        "remediation": "Set X-Content-Type-Options: nosniff for all dynamic responses and file downloads.",
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"],
    },
    "MISSING_REFERRER_POLICY": {
        "cwe_ids": ["CWE-200"],
        "owasp_category": "A05 Security Misconfiguration",
        "nist_control": "SC-7",
        "risk_level": "Low",
        "classification": FindingClassification.CRYPTOGRAPHIC_CONFIG_WEAKNESS.value,
        "technical_explanation": "Cross-origin navigation may leak sensitive URL fragments or query strings due to missing referrer controls.",
        "remediation": "Set a restrictive Referrer-Policy such as strict-origin-when-cross-origin or no-referrer.",
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"],
    },
    "MISSING_PERMISSIONS_POLICY": {
        "cwe_ids": ["CWE-693"],
        "owasp_category": "A05 Security Misconfiguration",
        "nist_control": "SC-8",
        "risk_level": "Low",
        "classification": FindingClassification.CRYPTOGRAPHIC_CONFIG_WEAKNESS.value,
        "technical_explanation": "Browser capabilities remain broadly enabled because feature-level permission controls are not constrained.",
        "remediation": "Define a restrictive Permissions-Policy that disables unnecessary browser features by default.",
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy"],
    },
    "WEAK_TLS_CONFIGURATION": {
        "cwe_ids": ["CWE-326", "CWE-327", "CWE-757"],
        "owasp_category": "A02 Cryptographic Failures",
        "nist_control": "SC-8",
        "risk_level": "High",
        "classification": FindingClassification.CRYPTOGRAPHIC_CONFIG_WEAKNESS.value,
        "technical_explanation": "The TLS posture is weak, typically due to legacy protocol versions, weak ciphers, or lack of forward secrecy.",
        "remediation": "Disable TLS 1.0/1.1, remove weak cipher suites, and prefer modern ECDHE-based configurations with AEAD ciphers.",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
    },
    "NO_PFS": {
        "cwe_ids": ["CWE-326"],
        "owasp_category": "A02 Cryptographic Failures",
        "nist_control": "SC-8",
        "risk_level": "High",
        "classification": FindingClassification.CRYPTOGRAPHIC_CONFIG_WEAKNESS.value,
        "technical_explanation": "The service does not provide perfect forward secrecy, so past sessions could be exposed if the server key is compromised.",
        "remediation": "Prefer ECDHE cipher suites and remove static key-exchange-only suites from the TLS configuration.",
        "references": ["https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security"],
    },
    "COOKIE_MISCONFIGURATION": {
        "cwe_ids": ["CWE-614", "CWE-1004"],
        "owasp_category": "A05 Security Misconfiguration",
        "nist_control": "SC-7",
        "risk_level": "Medium",
        "classification": FindingClassification.CRYPTOGRAPHIC_CONFIG_WEAKNESS.value,
        "technical_explanation": "Cookies are missing secure defaults such as HttpOnly, Secure, SameSite, or appropriate domain/path scoping.",
        "remediation": "Set Secure, HttpOnly, and SameSite on sensitive cookies, and narrow domain and path scope to the minimum required.",
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Cookies"],
    },
}

SOFTWARE_INDICATORS = {
    "apache",
    "nginx",
    "tomcat",
    "openssl",
    "wordpress",
    "django",
    "flask",
    "spring",
    "jquery",
    "bootstrap",
    "log4j",
    "postgresql",
    "mysql",
    "redis",
    "php",
    "ruby",
    "rails",
    "node",
    "express",
    "kubernetes",
    "docker",
}


def normalize_finding_key(value: str | None) -> str:
    if not value:
        return ""
    return value.strip().upper().replace(" ", "_").replace("-", "_")


def build_decision(
    finding_key: str | None,
    *,
    rule_id: str | None = None,
    severity: str | None = None,
    description: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> MappingDecision:
    normalized = normalize_finding_key(finding_key or rule_id)
    classification = classify_finding(
        title=finding_key,
        description=description,
        finding_type=(metadata or {}).get("type"),
        source=(metadata or {}).get("source"),
        tags=list((metadata or {}).get("tags") or []),
        evidence=metadata,
        metadata={**(metadata or {}), "rule_id": rule_id or (metadata or {}).get("rule_id")},
    )
    internal = FINDING_MAP.get(normalized)

    if internal:
        return MappingDecision(
            finding_key=normalized,
            cwe_ids=list(internal.get("cwe_ids") or []),
            owasp_category=internal.get("owasp_category"),
            nist_control=internal.get("nist_control"),
            requires_cve_lookup=False,
            risk_level=internal.get("risk_level", severity or "Medium"),
            technical_explanation=internal.get("technical_explanation", description or normalized),
            remediation=internal.get("remediation", "Review the affected control and apply the vendor or standards-based hardening guidance."),
            references=list(internal.get("references") or []),
            classification=internal.get("classification", classification.value),
        )

    if normalized in RULE_PROFILE_MAP:
        profile = RULE_PROFILE_MAP[normalized]
        return MappingDecision(
            finding_key=normalized,
            cwe_ids=list(profile.get("cwe_ids") or []),
            owasp_category=profile.get("owasp_category"),
            nist_control=profile.get("nist_control"),
            requires_cve_lookup=False,
            risk_level=severity or "Medium",
            technical_explanation=description or normalized,
            remediation="Apply the recommended control hardening for this internal rule finding.",
            references=[],
            classification=classification.value,
        )

    if is_software_vulnerability_classification(classification) and _looks_like_software_version(normalized, description, metadata):
        return MappingDecision(
            finding_key=normalize_finding_key(build_software_lookup_query(normalized, metadata)),
            cwe_ids=[],
            owasp_category="A06 Vulnerable and Outdated Components",
            nist_control="SA-11",
            requires_cve_lookup=True,
            risk_level=severity or "High",
            technical_explanation=description or "A software or framework version was detected and should be evaluated against public vulnerability intelligence.",
            remediation="Upgrade to a supported, patched release and verify the fix against advisories and vendor release notes.",
            references=[],
            classification=FindingClassification.SOFTWARE_VULNERABILITY.value,
        )

    return MappingDecision(
        finding_key=normalized,
        cwe_ids=[],
        owasp_category=None,
        nist_control=None,
        requires_cve_lookup=is_software_vulnerability_classification(classification) and bool(normalized and any(token in normalized for token in ("CVE", "VERSION", "PACKAGE", "DEPENDENCY"))),
        risk_level=severity or "Medium",
        technical_explanation=description or "This finding does not map to a known internal weakness profile.",
        remediation="Review the finding context and determine whether it reflects a software version, dependency, or configuration issue.",
        references=[],
        classification=classification.value,
    )


def _looks_like_software_version(finding_key: str, description: str | None, metadata: dict[str, Any] | None) -> bool:
    haystack = " ".join(
        str(part)
        for part in [finding_key, description or "", metadata.get("product") if metadata else "", metadata.get("vendor") if metadata else ""]
    ).lower()
    if any(token in haystack for token in SOFTWARE_INDICATORS):
        if any(char.isdigit() for char in haystack):
            return True
    return any(marker in haystack for marker in (" version ", " v", " release ", " dependency ", " package ", " advisory "))
