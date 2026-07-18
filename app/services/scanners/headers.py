from __future__ import annotations

import re
from urllib.parse import urlparse

from app.config import settings
from app.core.http_client import create_async_client, request_with_retry
from app.services.models.pipeline import RawFinding, ScanContext, ScanTarget
from app.services.scanners.base import ScannerResult, TargetScanner


REQUIRED_HEADERS = {
    "content-security-policy": (
        "MISSING_CSP",
        "Missing Content-Security-Policy",
        "Define a restrictive Content-Security-Policy to reduce script injection and data exfiltration impact.",
    ),
    "strict-transport-security": (
        "NO_HSTS",
        "Missing Strict-Transport-Security",
        "Set Strict-Transport-Security with max-age of at least 31536000 after validating HTTPS coverage.",
    ),
    "x-frame-options": (
        "MISSING_X_FRAME_OPTIONS",
        "Missing X-Frame-Options",
        "Set X-Frame-Options to DENY or SAMEORIGIN, or use CSP frame-ancestors.",
    ),
    "x-content-type-options": (
        "MISSING_X_CONTENT_TYPE",
        "Missing X-Content-Type-Options",
        "Set X-Content-Type-Options: nosniff on all dynamic responses and downloads.",
    ),
    "referrer-policy": (
        "MISSING_REFERRER_POLICY",
        "Missing Referrer-Policy",
        "Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin or no-referrer.",
    ),
    "permissions-policy": (
        "MISSING_PERMISSIONS_POLICY",
        "Missing Permissions-Policy",
        "Disable browser features that the application does not need.",
    ),
    "cross-origin-embedder-policy": (
        "MISSING_COEP",
        "Missing Cross-Origin-Embedder-Policy",
        "Set Cross-Origin-Embedder-Policy where cross-origin isolation is required.",
    ),
    "cross-origin-resource-policy": (
        "MISSING_CORP",
        "Missing Cross-Origin-Resource-Policy",
        "Set Cross-Origin-Resource-Policy to same-origin or same-site for sensitive resources.",
    ),
    "cross-origin-opener-policy": (
        "MISSING_COOP",
        "Missing Cross-Origin-Opener-Policy",
        "Set Cross-Origin-Opener-Policy: same-origin for pages that should isolate browsing contexts.",
    ),
    "cache-control": (
        "MISSING_CACHE_CONTROL",
        "Missing Cache-Control",
        "Set Cache-Control appropriate to the page; sensitive pages should use no-store.",
    ),
}


class HeaderScanner(TargetScanner):
    name = "headers"
    supported_kinds = {"url"}

    async def scan(self, target: ScanTarget, context: ScanContext) -> ScannerResult:
        # Target admission happens before queueing. Do not follow redirects here:
        # a public URL can redirect the worker to a private address after admission.
        async with create_async_client(timeout=settings.INTELLIGENCE_REQUEST_TIMEOUT_SECONDS, follow_redirects=False) as client:
            response = await request_with_retry(client, "GET", target.value)
        if response is None:
            return ScannerResult(metadata={"error": "Unable to fetch response headers"})
        findings = self._analyze_headers(dict(response.headers), target.value, response.status_code)
        return ScannerResult(findings=findings, metadata={"status_code": response.status_code})

    def _analyze_headers(self, headers: dict[str, str], url: str, status_code: int = 200) -> list[RawFinding]:
        findings: list[RawFinding] = []
        header_map = {key.lower(): value for key, value in headers.items()}
        sensitive = _is_sensitive_url(url)

        for header, (rule_id, title, remediation) in REQUIRED_HEADERS.items():
            if header in header_map:
                continue
            if header == "cache-control" and not sensitive:
                continue
            findings.append(self._header_finding(
                rule_id=rule_id,
                title=title,
                description=f"{title} on {url}",
                severity="Medium" if header in {"content-security-policy", "strict-transport-security"} else "Low",
                evidence={"header": header, "present": False, "url": url},
                remediation=remediation,
                url=url,
                status_code=status_code,
                headers=headers,
            ))

        csp = header_map.get("content-security-policy")
        if csp:
            weak_tokens = [token for token in ("unsafe-inline", "unsafe-eval", "*") if token in csp]
            if weak_tokens:
                findings.append(self._header_finding(
                    rule_id="WEAK_CSP",
                    title="Weak Content-Security-Policy",
                    description="Content-Security-Policy contains unsafe directives or wildcards.",
                    severity="Medium",
                    evidence={"header": "content-security-policy", "weak_tokens": weak_tokens, "value": csp},
                    remediation="Remove unsafe-inline, unsafe-eval, and broad wildcards unless a documented exception is required.",
                    url=url,
                    status_code=status_code,
                    headers=headers,
                ))

        hsts = header_map.get("strict-transport-security")
        if hsts:
            max_age = _hsts_max_age(hsts)
            if max_age is None:
                findings.append(self._header_finding(
                    rule_id="WEAK_HSTS",
                    title="HSTS Missing max-age",
                    description="Strict-Transport-Security is present but missing max-age.",
                    severity="Medium",
                    evidence={"header": "strict-transport-security", "value": hsts},
                    remediation="Set max-age to at least 31536000 seconds after confirming HTTPS readiness.",
                    url=url,
                    status_code=status_code,
                    headers=headers,
                ))
            elif max_age < 31536000:
                findings.append(self._header_finding(
                    rule_id="WEAK_HSTS",
                    title="HSTS max-age Too Low",
                    description="Strict-Transport-Security max-age is below one year.",
                    severity="Low",
                    evidence={"header": "strict-transport-security", "max_age": max_age, "value": hsts},
                    remediation="Increase HSTS max-age to at least 31536000 seconds.",
                    url=url,
                    status_code=status_code,
                    headers=headers,
                ))

        xfo = header_map.get("x-frame-options")
        if xfo and xfo.upper() not in {"DENY", "SAMEORIGIN"} and not xfo.upper().startswith("ALLOW-FROM"):
            findings.append(self._header_finding(
                rule_id="INVALID_X_FRAME_OPTIONS",
                title="Invalid X-Frame-Options Value",
                description="X-Frame-Options has an invalid or unsupported value.",
                severity="Low",
                evidence={"header": "x-frame-options", "value": xfo},
                remediation="Use DENY or SAMEORIGIN, or move framing policy to CSP frame-ancestors.",
                url=url,
                status_code=status_code,
                headers=headers,
            ))

        cache_control = header_map.get("cache-control")
        if sensitive and cache_control and "no-store" not in cache_control.lower():
            findings.append(self._header_finding(
                rule_id="WEAK_CACHE_CONTROL",
                title="Cache-Control Weak on Sensitive Page",
                description="Sensitive page response does not include Cache-Control: no-store.",
                severity="Medium",
                evidence={"header": "cache-control", "value": cache_control, "url": url},
                remediation="Set Cache-Control: no-store for authenticated, token, account, admin, and payment pages.",
                url=url,
                status_code=status_code,
                headers=headers,
            ))

        set_cookie = header_map.get("set-cookie")
        if set_cookie:
            cookie_flags = set_cookie.lower()
            missing_flags = [
                flag for flag in ("secure", "httponly", "samesite")
                if flag not in cookie_flags
            ]
            if missing_flags:
                findings.append(self._header_finding(
                    rule_id="INSECURE_COOKIE_FLAGS",
                    title="Response Cookie Missing Security Flags",
                    description="A response Set-Cookie header is missing recommended security attributes.",
                    severity="Medium",
                    evidence={"header": "set-cookie", "missing_flags": missing_flags},
                    remediation="Set Secure, HttpOnly, and an appropriate SameSite attribute on security-sensitive cookies.",
                    url=url,
                    status_code=status_code,
                    headers=headers,
                ))

        return findings

    def _header_finding(
        self,
        *,
        rule_id: str,
        title: str,
        description: str,
        severity: str,
        evidence: dict,
        remediation: str,
        url: str,
        status_code: int,
        headers: dict[str, str],
    ) -> RawFinding:
        return self._finding(
            finding_type="header",
            title=title,
            description=description,
            severity=severity,
            evidence={"rule_id": rule_id, "category": "Missing secure headers", **evidence},
            location=url,
            confidence=0.88,
            confidence_label="probable",
            raw_data={"rule_id": rule_id, "status_code": status_code, "headers": headers},
            target=url,
            tags=["headers", "web", "missing-secure-headers"],
            remediation=remediation,
            references=["OWASP Secure Headers Project", "CWE-693"],
        )


def _hsts_max_age(value: str) -> int | None:
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _is_sensitive_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(part in path for part in ("login", "logout", "account", "admin", "dashboard", "token", "reset", "payment", "checkout", "profile"))
