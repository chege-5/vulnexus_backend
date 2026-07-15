import asyncio
import csv
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZipFile
from jinja2 import Environment, select_autoescape
from app.config import settings
from app.services.report_renderer import get_report_renderer
from app.utils.logger import get_logger
from app.utils.redaction import redact_data, redact_json_string, redact_text

logger = get_logger(__name__)

HTML_ENV = Environment(
    autoescape=select_autoescape(
        enabled_extensions=("html", "htm", "xml"),
        default_for_string=True,
        default=True,
    )
)

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulNexus Security Audit Report</title>
<style>
@page { margin: 22mm 16mm 18mm 16mm; }
body {
    font-family: 'Segoe UI', Arial, sans-serif;
    margin: 0;
    color: #0f172a;
    background: #f4f7fb;
}
.page {
    padding: 28px;
}
.cover {
    background: linear-gradient(135deg, #0f172a 0%, #1d4ed8 100%);
    color: white;
    border-radius: 24px;
    padding: 42px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
}
.cover::after {
    content: 'CONFIDENTIAL';
    position: absolute;
    right: -8px;
    top: 24px;
    transform: rotate(12deg);
    font-size: 72px;
    font-weight: 800;
    letter-spacing: 0.18em;
    opacity: 0.08;
}
.brand {
    text-transform: uppercase;
    letter-spacing: 0.24em;
    font-size: 12px;
    opacity: 0.9;
}
.cover h1 {
    margin: 14px 0 8px 0;
    font-size: 34px;
}
.cover p {
    margin: 0 0 8px 0;
    max-width: 760px;
    line-height: 1.6;
}
.summary-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 12px;
    margin: 20px 0;
}
.metric {
    background: white;
    border: 1px solid #d8e0ef;
    border-radius: 16px;
    padding: 16px;
    box-shadow: 0 10px 24px rgba(15, 23, 42, 0.06);
}
.metric-label {
    display: block;
    color: #64748b;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 8px;
}
.metric-value {
    font-size: 28px;
    font-weight: 800;
    color: #0f172a;
}
.section {
    background: white;
    border: 1px solid #d8e0ef;
    border-radius: 20px;
    padding: 24px;
    margin-bottom: 18px;
    box-shadow: 0 10px 24px rgba(15, 23, 42, 0.04);
}
.section h2 {
    margin: 0 0 14px 0;
    font-size: 22px;
    color: #0f172a;
}
.section h3 {
    margin: 0 0 10px 0;
    color: #1d4ed8;
}
.muted {
    color: #64748b;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 12px;
}
th, td {
    border-bottom: 1px solid #e2e8f0;
    padding: 12px 10px;
    text-align: left;
    vertical-align: top;
    font-size: 13px;
}
th {
    background: #eff6ff;
    color: #0f172a;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}
.severity-critical { color: #b91c1c; font-weight: 700; }
.severity-high { color: #ea580c; font-weight: 700; }
.severity-medium { color: #ca8a04; font-weight: 700; }
.severity-low { color: #15803d; font-weight: 700; }
.pill {
    display: inline-block;
    padding: 6px 10px;
    border-radius: 999px;
    background: #e2e8f0;
    font-size: 12px;
    font-weight: 700;
}
.pill.critical { background: #fee2e2; color: #991b1b; }
.pill.high { background: #ffedd5; color: #9a3412; }
.pill.medium { background: #fef3c7; color: #92400e; }
.pill.low { background: #dcfce7; color: #166534; }
.finding {
    border-left: 4px solid #1d4ed8;
    padding: 14px 16px;
    margin: 10px 0;
    background: #f8fbff;
    border-radius: 14px;
}
.finding pre {
    white-space: pre-wrap;
    word-break: break-word;
    background: #0f172a;
    color: #e2e8f0;
    padding: 12px;
    border-radius: 10px;
    overflow-x: auto;
}
.toc {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
}
.toc span {
    background: #eff6ff;
    border: 1px solid #dbeafe;
    border-radius: 12px;
    padding: 10px 12px;
    font-size: 13px;
}
footer {
    margin-top: 24px;
    color: #64748b;
    font-size: 12px;
    text-align: center;
}
.watermark {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%) rotate(-18deg);
    font-size: 88px;
    font-weight: 900;
    letter-spacing: 0.18em;
    color: rgba(15, 23, 42, 0.05);
    pointer-events: none;
}
@media print {
    body { background: white; }
    .page { padding: 0; }
    .section, .metric, .cover { box-shadow: none; }
    .section { break-inside: avoid; page-break-inside: avoid; }
    .finding { break-inside: avoid; page-break-inside: avoid; }
    table { break-inside: auto; }
    thead { display: table-header-group; }
    tr { break-inside: avoid; page-break-inside: avoid; }
}
</style>
</head>
<body>
<div class="watermark">CONFIDENTIAL</div>
<div class="page">
<section class="cover">
    <div class="brand">VulNexus Security Audit</div>
    <h1>{{ target }}</h1>
    <p>Regex-based static analysis, active TLS probing, and HTTP header inspection report for {{ scan_type|upper }} targets. This artifact summarizes representative security weakness findings for review and demonstration.</p>
    <p><strong>Report ID:</strong> {{ scan_id }}<br><strong>Generated:</strong> {{ generated_at }}<br><strong>Started:</strong> {{ started_at or 'Not Applicable' }}<br><strong>Finished:</strong> {{ finished_at or 'Not Applicable' }}</p>
</section>

<section class="section">
    <h2>Executive Summary</h2>
    <div class="summary-grid">
        <div class="metric"><span class="metric-label">Overall Score</span><span class="metric-value">{{ overall_score }} / 100</span></div>
        <div class="metric"><span class="metric-label">Audit Verdict</span><span class="metric-value">{{ overall_verdict }}</span></div>
        <div class="metric"><span class="metric-label">Findings</span><span class="metric-value">{{ vuln_count }}</span></div>
        <div class="metric"><span class="metric-label">Critical</span><span class="metric-value">{{ severity_counts.get('Critical', 0) }}</span></div>
    </div>
    <p class="muted">This assessment identified {{ vuln_count }} findings across application code, repository assets, and cryptographic posture. Review the sections below for prioritized remediation actions and compliance status.</p>
    {% if verdict_reason %}
    <p><strong>Verdict rationale:</strong> {{ verdict_reason }}</p>
    {% endif %}
</section>

<section class="section">
    <h2>Table of Contents</h2>
    <div class="toc">
        <span>Executive Summary</span>
        <span>Risk Summary</span>
        <span>Repository and Scan Context</span>
        <span>Findings</span>
        <span>Compliance Mapping</span>
        <span>Recommendations</span>
    </div>
</section>

<section class="section">
    <h2>Risk Summary</h2>
    <div class="summary-grid">
        <div class="metric"><span class="metric-label">Critical</span><span class="metric-value">{{ severity_counts.get('Critical', 0) }}</span></div>
        <div class="metric"><span class="metric-label">High</span><span class="metric-value">{{ severity_counts.get('High', 0) }}</span></div>
        <div class="metric"><span class="metric-label">Medium</span><span class="metric-value">{{ severity_counts.get('Medium', 0) }}</span></div>
        <div class="metric"><span class="metric-label">Low</span><span class="metric-value">{{ severity_counts.get('Low', 0) }}</span></div>
    </div>
</section>

<section class="section">
    <h2>Findings</h2>
    {% if vulnerabilities %}
    <table>
        <thead>
            <tr>
                <th>#</th><th>Rule ID</th><th>Rule Name</th><th>Category</th><th>Severity</th><th>Confidence</th><th>Affected Asset</th><th>Line</th><th>Column</th><th>Matched Pattern</th><th>Evidence</th><th>Recommendation</th><th>CWE / OWASP</th>
            </tr>
        </thead>
        <tbody>
        {% for v in vulnerabilities %}
            <tr>
                <td>{{ loop.index }}</td>
                <td>{{ v.rule_id }}</td>
                <td>{{ v.display_title }}</td>
                <td>{{ v.display_category }}</td>
                <td><span class="pill {{ v.severity|lower }}">{{ v.severity }}</span></td>
                <td>{{ v.display_confidence }}</td>
                <td>{{ v.display_location }}</td>
                <td>{{ v.line_number or 'Not Applicable' }}</td>
                <td>{{ v.display_column }}</td>
                <td>{{ v.display_matched_pattern }}</td>
                <td>{{ v.display_evidence }}</td>
                <td>{{ v.remediation or v.recommendation or 'Review and remediate using current security guidance.' }}</td>
                <td>{{ v.display_mapping }}</td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p>No vulnerabilities detected.</p>
    {% endif %}
</section>

{% if ai_insight or vulnerabilities %}
<section class="section">
    <h2>Threat Intelligence and Attack Story</h2>
    <div class="finding">
        <h3>Operational Narrative</h3>
        <p>{{ ai_insight.summary if ai_insight and ai_insight.summary else 'No narrative available.' }}</p>
    </div>
    {% for v in vulnerabilities[:5] %}
    <div class="finding">
        <h3>{{ v.display_title }}</h3>
        <p>{{ v.attack_story or (v.knowledge.attack.attack_story if v.knowledge and v.knowledge.attack and v.knowledge.attack.attack_story else v.description) }}</p>
    </div>
    {% endfor %}
</section>
{% endif %}

{% if provider_statuses %}
<section class="section">
    <h2>External Intelligence Provider Status</h2>
    <p class="muted">Provider restrictions do not invalidate the completed scan. They are recorded here so the report does not imply unavailable data was retrieved.</p>
    <table>
        <thead><tr><th>Provider</th><th>Status</th><th>Details</th></tr></thead>
        <tbody>
        {% for status in provider_statuses %}
            <tr>
                <td>{{ status.provider }}</td>
                <td>{{ status.status or 'skipped' }}</td>
                <td>{{ status.message or status.error or 'No usable provider data was returned.' }}</td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
</section>
{% endif %}

<section class="section">
    <h2>Compliance Mapping</h2>
    <p class="muted">Each finding should be reviewed against OWASP Top 10, OWASP ASVS, NIST, CWE, CVE/CVSS, MITRE ATT&amp;CK, and CIS Controls where relevant.</p>
    <p><span class="pill low">Pass</span> <span class="pill high">Warning</span> <span class="pill critical">Fail</span></p>
    {% if compliance_checks %}
    <table>
        <thead>
            <tr><th>Standard</th><th>Category</th><th>Result</th><th>Score</th><th>Details</th></tr>
        </thead>
        <tbody>
        {% for check in compliance_checks %}
            <tr>
                <td>{{ check.standard }}</td>
                <td>{{ check.category or 'Not Applicable' }}</td>
                <td>{{ check.result }}</td>
                <td>{{ check.score if check.score is not none else 'Not Applicable' }}</td>
                <td>{{ check.details.finding if check.details and check.details.finding else 'See finding evidence' }}</td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p>No structured compliance checks were generated for this scan.</p>
    {% endif %}
</section>

{% if ai_insight %}
<section class="section">
    <h2>AI Audit Insight</h2>
    <p><strong>{{ ai_insight.title }}</strong></p>
    <p>{{ ai_insight.summary }}</p>
</section>
{% endif %}

{% if cve_details %}
<section class="section">
    <h2>CVE References</h2>
    <table>
        <thead>
            <tr><th>CVE ID</th><th>CVSS</th><th>Summary</th><th>Published</th></tr>
        </thead>
        <tbody>
        {% for c in cve_details %}
            <tr>
                <td>{{ c.cve_id }}</td>
                <td>{{ c.cvss_score or 'Not Applicable' }}</td>
                <td>{{ c.summary or 'Not Applicable' }}</td>
                <td>{{ c.published_date or 'Not Applicable' }}</td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
</section>
{% endif %}

<section class="section">
    <h2>Recommendations and Mitigation Plan</h2>
    {% for v in vulnerabilities %}
        {% if v.remediation %}
        <div class="finding">
            <h3>{{ v.display_title }} - {{ v.severity }}</h3>
            <p>{{ v.remediation }}</p>
        </div>
        {% endif %}
    {% endfor %}
    <div class="finding">
        <h3>General Recommendations</h3>
        <ul>
            <li>Replace MD5/SHA-1 with SHA-256 or SHA-3</li>
            <li>Replace DES/3DES/RC2 with AES-256-GCM</li>
            <li>Use RSA >= 2048 bits or ECDSA >= P-256</li>
            <li>Enable TLS 1.2+ and disable older versions</li>
            <li>Enable HSTS with a minimum max-age of 31536000</li>
            <li>Use certificates from trusted CAs</li>
            <li>Use cryptographically secure random number generators</li>
            <li>Store secrets in a managed vault, not code or config files</li>
        </ul>
    </div>
</section>

<footer>
    <div>Generated by VulNexus - Cryptography and Security Weakness Scanner</div>
    <div>Report ID {{ scan_id }} | {{ generated_at }}</div>
</footer>
</div>
</body>
</html>
"""

REMEDIATION_MAP = {
    "WEAK_HASH_MD5": "Replace MD5 with SHA-256 or SHA-3. MD5 is vulnerable to collision attacks (RFC 6151).",
    "WEAK_HASH_SHA1": "Replace SHA-1 with SHA-256 or SHA-3. SHA-1 is vulnerable to collision attacks (NIST SP 800-131A).",
    "WEAK_CIPHER_DES": "Replace DES with AES-256-GCM. DES has a 56-bit key which is trivially brute-forceable.",
    "WEAK_CIPHER_RC2": "Replace RC2 with AES-256-GCM. RC2 is considered cryptographically weak.",
    "WEAK_CIPHER_AES-ECB": "Replace ECB mode with GCM or CBC with proper IV. ECB leaks patterns in plaintext.",
    "WEAK_CIPHER_3DES": "Replace 3DES with AES-256-GCM or ChaCha20-Poly1305.",
    "WEAK_CIPHER_RC4": "Disable RC4 and use modern AEAD ciphers.",
    "WEAK_CIPHER_BLOWFISH": "Prefer AES-GCM or ChaCha20-Poly1305 for new encryption.",
    "CBC_WITHOUT_AUTH": "Use an authenticated encryption mode such as AES-GCM or add encrypt-then-MAC.",
    "SMALL_RSA_KEY": "Use RSA key size of 2048 bits minimum (NIST recommendation). Consider 4096 for long-term security.",
    "SMALL_AES_KEY": "Use AES-128 minimum; AES-256 recommended for sensitive data.",
    "HARDCODED_KEY": "Move keys to environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
    "INSECURE_RANDOM": "Use os.urandom(), secrets module (Python), or java.security.SecureRandom (Java).",
    "WEAK_TLS_VERSION": "Disable TLS 1.0/1.1 and enable TLS 1.2+ (PCI DSS 3.2 requirement).",
    "SELF_SIGNED_CERT": "Use certificates from a trusted CA. Use Let's Encrypt for free certificates.",
    "NO_HSTS": "Add Strict-Transport-Security header with max-age=31536000; includeSubDomains.",
    "NO_FORWARD_SECRECY": "Configure server to prefer ECDHE cipher suites for forward secrecy.",
    "EXPIRED_CERT": "Renew the expired certificate immediately. Set up automated renewal.",
    "CERT_NEAR_EXPIRY": "Renew or rotate the certificate before expiry and monitor certificate lifecycle automation.",
    "CERT_HOSTNAME_MISMATCH": "Reissue the certificate with SAN entries that exactly match the service hostname.",
    "WEAK_CERT_CRYPTO": "Reissue the certificate using SHA-256 or stronger signatures and RSA >= 2048 bits or ECDSA P-256+ keys.",
    "UNTRUSTED_CERT_CHAIN": "Install a CA-trusted certificate and include the correct intermediate certificates in the served chain.",
    "WEAK_CIPHER_SUITE": "Disable NULL, EXPORT, RC4, DES, 3DES, anonymous, and non-forward-secret suites. Prefer TLS 1.3 or ECDHE AES-GCM/ChaCha20 suites.",
    "MISSING_MODERN_TLS": "Enable the required modern TLS protocol version while retaining TLS 1.2 only where compatibility requires it.",
    "WEAK_HSTS": "Increase Strict-Transport-Security max-age to at least 31536000 seconds and consider includeSubDomains after validation.",
    "STATIC_IV": "Generate a unique unpredictable IV/nonce per encryption operation and store it with the ciphertext when required.",
    "STATIC_SALT": "Generate a unique random salt per password or key derivation operation.",
    "WEAK_KDF": "Use a modern KDF such as Argon2id, scrypt, or PBKDF2 with current iteration guidance and per-secret random salts.",
    "WEAK_HASH_CRC32_SECURITY": "Use a cryptographic hash or MAC for security-sensitive integrity checks.",
    "WEAK_JWT_SECRET": "Use a high-entropy JWT secret of at least 32 bytes loaded from a secret manager.",
    "CONFIG_STORED_SECRET": "Store runtime secrets in a managed secret store and inject them at deployment time.",
    "MISSING_CSP": "Define a restrictive Content-Security-Policy.",
    "WEAK_CSP": "Remove unsafe-inline, unsafe-eval, and broad wildcards from CSP where possible.",
    "MISSING_X_FRAME_OPTIONS": "Set X-Frame-Options to DENY or SAMEORIGIN, or use CSP frame-ancestors.",
    "MISSING_X_CONTENT_TYPE": "Set X-Content-Type-Options: nosniff.",
    "MISSING_REFERRER_POLICY": "Set a privacy-preserving Referrer-Policy.",
    "MISSING_PERMISSIONS_POLICY": "Set a restrictive Permissions-Policy.",
    "MISSING_COEP": "Set Cross-Origin-Embedder-Policy where cross-origin isolation is required.",
    "MISSING_CORP": "Set Cross-Origin-Resource-Policy for sensitive resources.",
    "MISSING_COOP": "Set Cross-Origin-Opener-Policy: same-origin where appropriate.",
    "MISSING_CACHE_CONTROL": "Set Cache-Control on sensitive pages, using no-store for authenticated or token-bearing pages.",
    "WEAK_CACHE_CONTROL": "Set Cache-Control: no-store for sensitive authenticated pages.",
    "INVALID_X_FRAME_OPTIONS": "Use DENY or SAMEORIGIN for X-Frame-Options.",
    "USES_MD5": "Replace MD5 with SHA-256 or SHA-3.",
    "USES_SHA1": "Replace SHA-1 with SHA-256 or SHA-3.",
    "USES_DES": "Replace DES with AES-256-GCM.",
    "USES_RC2": "Replace RC2 with AES-256-GCM.",
    "USES_ECB": "Replace ECB mode with GCM or CBC.",
    "RSA_SMALL": "Use RSA ≥ 2048 bits.",
    "AES_SMALL": "Use AES ≥ 128 bits.",
    "NO_PFS": "Enable ECDHE cipher suites for forward secrecy.",
    "WEAK_TLS": "Upgrade to TLS 1.2 or higher.",
    "SELF_SIGNED": "Use a certificate from a trusted CA.",
}

FINDING_TITLE_MAP = {
    "transport:tls_pki_crypto_posture": "TLS and PKI Security Finding",
    "external_reputation": "Infrastructure Reputation Signal",
    "WEAK_TLS_VERSION": "Deprecated TLS Protocol Supported",
    "WEAK_CIPHER_SUITE": "Weak Cipher Suites Enabled",
    "MISSING_MODERN_TLS": "Modern TLS 1.3 Not Supported",
    "WEAK_HSTS": "HTTP Strict Transport Security Not Properly Configured",
    "NO_HSTS": "HTTP Strict Transport Security Not Enabled",
    "HARDCODED_KEY": "Hardcoded Cryptographic Secret Detected",
    "STATIC_IV": "Static Initialization Vector Detected",
    "WEAK_HASH_MD5": "Weak Cryptographic Hash (MD5) Used",
    "WEAK_HASH_SHA1": "Weak Cryptographic Hash (SHA-1) Used",
    "EXPIRED_CERT": "Expired X.509 Certificate",
    "SELF_SIGNED_CERT": "Self-Signed Certificate Presented",
    "CERT_HOSTNAME_MISMATCH": "Certificate Hostname Validation Failed",
    "WEAK_CERT_CRYPTO": "Weak Certificate Cryptography Detected",
    "UNTRUSTED_CERT_CHAIN": "Certificate Trust Validation Failed",
    "NO_FORWARD_SECRECY": "Forward Secrecy Not Supported",
    "CERT_NEAR_EXPIRY": "TLS Certificate Near Expiration",
    "STATIC_SALT": "Static Cryptographic Salt Detected",
    "WEAK_KDF": "Weak Key Derivation Function Used",
    "WEAK_HASH_CRC32_SECURITY": "CRC32 Used for Security-Sensitive Logic",
    "WEAK_JWT_SECRET": "Weak JWT Secret Detected",
    "CONFIG_STORED_SECRET": "Secret Stored in Configuration File",
    "WEAK_CIPHER_3DES": "Deprecated Triple DES Cipher Used",
    "WEAK_CIPHER_RC4": "Deprecated RC4 Cipher Used",
    "WEAK_CIPHER_BLOWFISH": "Legacy Blowfish Cipher Used",
    "CBC_WITHOUT_AUTH": "CBC Mode Without Visible Authentication",
    "INSECURE_RANDOM": "Insecure Random Number Generator Used",
    "SMALL_RSA_KEY": "Insufficient RSA Key Length",
    "SMALL_AES_KEY": "Insufficient AES Key Length",
    "MISSING_CSP": "Missing Content-Security-Policy",
    "WEAK_CSP": "Weak Content-Security-Policy",
    "MISSING_X_FRAME_OPTIONS": "Missing X-Frame-Options",
    "MISSING_X_CONTENT_TYPE": "Missing X-Content-Type-Options",
    "MISSING_REFERRER_POLICY": "Missing Referrer-Policy",
    "MISSING_PERMISSIONS_POLICY": "Missing Permissions-Policy",
    "MISSING_COEP": "Missing Cross-Origin-Embedder-Policy",
    "MISSING_CORP": "Missing Cross-Origin-Resource-Policy",
    "MISSING_COOP": "Missing Cross-Origin-Opener-Policy",
    "MISSING_CACHE_CONTROL": "Missing Cache-Control",
    "WEAK_CACHE_CONTROL": "Weak Cache-Control on Sensitive Page",
    "INVALID_X_FRAME_OPTIONS": "Invalid X-Frame-Options Value",
}


def get_finding_title(finding: dict) -> str:
    explicit = finding.get("title") or finding.get("name")
    if explicit and not _looks_internal(explicit):
        return explicit
    rule_id = finding.get("rule_id") or explicit or "Security Finding"
    return FINDING_TITLE_MAP.get(rule_id, _humanize_identifier(str(rule_id)))


def _looks_internal(value: str) -> bool:
    text = str(value or "")
    return text.isupper() or ":" in text or text.endswith("_layer") or text in {"external_reputation", "general:application"}


def _humanize_identifier(value: str) -> str:
    last = value.split(":")[-1] if ":" in value else value
    words = last.replace("_", " ").replace("-", " ").split()
    if not words:
        return "Security Finding"
    replacements = {"tls": "TLS", "hsts": "HSTS", "md5": "MD5", "sha1": "SHA-1", "x509": "X.509"}
    return " ".join(replacements.get(word.lower(), word.capitalize()) for word in words)


def _format_cvss(value) -> str:
    if value is None or value == "" or value == "N/A":
        return "Not Applicable"
    try:
        return f"{float(value):.1f}"
    except (TypeError, ValueError):
        return "Not Applicable"


def _format_confidence(value) -> str:
    if value is None or value == "":
        return "High Confidence"
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return str(value).replace("_", " ")
    return f"{round(numeric * 100 if numeric <= 1 else numeric)}%"


def _format_evidence(value) -> str:
    if not value:
        return "Not Applicable"
    value = redact_data(value)
    if isinstance(value, dict):
        raw = value.get("raw_evidence")
        if raw:
            return redact_json_string(raw[0])
        clean = {key: item for key, item in value.items() if key not in {"rule_id", "scanner", "source_scanner"} and item not in (None, "", [])}
        return redact_json_string(clean or value)
    return redact_text(value)


def _display_category(finding: dict) -> str:
    explicit = finding.get("category") or finding.get("evidence", {}).get("category")
    if explicit:
        return str(explicit)
    rule_id = str(finding.get("rule_id") or "")
    if rule_id.startswith("WEAK_HASH"):
        return "Weak hashing"
    if rule_id in {"HARDCODED_KEY"}:
        return "Hardcoded keys"
    if rule_id == "INSECURE_RANDOM":
        return "Insecure randomness"
    if rule_id in {"STATIC_IV", "STATIC_SALT", "WEAK_JWT_SECRET", "CONFIG_STORED_SECRET"}:
        return "Poor key management"
    if rule_id in {"WEAK_TLS_VERSION", "WEAK_CIPHER_SUITE", "MISSING_MODERN_TLS", "NO_FORWARD_SECRECY", "NO_HSTS", "WEAK_HSTS"}:
        return "TLS misconfiguration"
    if rule_id.startswith("MISSING_") or rule_id in {"WEAK_CSP", "WEAK_CACHE_CONTROL", "INVALID_X_FRAME_OPTIONS"}:
        return "Missing secure headers"
    if rule_id.startswith("WEAK_CIPHER") or rule_id in {"CBC_WITHOUT_AUTH", "WEAK_KDF", "SMALL_RSA_KEY", "SMALL_AES_KEY"}:
        return "Weak cryptographic modes"
    return "Security finding"


def _format_mapping(finding: dict) -> str:
    cwes = finding.get("cwe_ids") or finding.get("compliance_mapping", {}).get("cwe_ids") or []
    owasp = finding.get("owasp_category") or finding.get("compliance_mapping", {}).get("owasp_category")
    parts = []
    if cwes:
        parts.append(", ".join(cwes))
    if owasp:
        parts.append(str(owasp))
    return " / ".join(parts) if parts else "Not Applicable"


def prepare_findings_for_report(vulnerabilities: list[dict]) -> list[dict]:
    prepared = []
    for finding in vulnerabilities:
        item = redact_data(dict(finding))
        if not isinstance(item.get("evidence"), dict):
            item["evidence"] = {}
        item["display_title"] = redact_text(get_finding_title(item))
        item["display_category"] = _display_category(item)
        item["display_confidence"] = _format_confidence(item.get("confidence"))
        item["display_cvss"] = _format_cvss(item.get("cvss_score"))
        item["display_cve"] = item.get("cve_id") or "Not Applicable"
        item["display_evidence"] = _format_evidence(item.get("evidence"))
        item["display_location"] = redact_text(item.get("file_path") or item.get("location") or item.get("target") or "Not Applicable")
        item["display_explanation"] = redact_text(item.get("explanation") or item.get("description") or "Review the evidence and affected asset.")
        item["display_mapping"] = _format_mapping(item)
        evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        item["display_matched_pattern"] = redact_text(evidence.get("matched_pattern") or evidence.get("regex") or "Not Applicable")
        item["display_column"] = item.get("column_number") or evidence.get("column_number") or "Not Applicable"
        if not item.get("remediation") and item.get("rule_id"):
            item["remediation"] = get_remediation(item["rule_id"])
        item["remediation"] = redact_text(item.get("remediation") or "")
        item["recommendation"] = redact_text(item.get("recommendation") or "")
        prepared.append(item)
    return prepared


def get_remediation(rule_id: str) -> str:
    return REMEDIATION_MAP.get(rule_id, "Review and update the cryptographic configuration per current best practices.")


def generate_html_report(
    scan_id: str,
    target: str,
    scan_type: str,
    overall_score: float,
    vulnerabilities: list[dict],
    cve_details: list[dict],
    compliance_checks: list[dict] | None = None,
    audit_verdict: dict | None = None,
    ai_insight: dict | None = None,
    provider_statuses: list[dict] | None = None,
    started_at: Optional[str] = None,
    finished_at: Optional[str] = None,
) -> str:
    target = redact_text(target)
    cve_details = redact_data(cve_details)
    compliance_checks = redact_data(compliance_checks or [])
    audit_verdict = redact_data(audit_verdict or {})
    ai_insight = redact_data(ai_insight or {})
    provider_statuses = redact_data(provider_statuses or [])
    vulnerabilities = prepare_findings_for_report(vulnerabilities)

    severity_counts = {}
    for v in vulnerabilities:
        sev = v.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if overall_score >= 75:
        score_class = "critical"
    elif overall_score >= 50:
        score_class = "high"
    elif overall_score >= 25:
        score_class = "medium"
    else:
        score_class = "low"

    template = HTML_ENV.from_string(REPORT_TEMPLATE)
    return template.render(
        scan_id=scan_id,
        target=target,
        scan_type=scan_type,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        started_at=started_at,
        finished_at=finished_at,
        overall_score=round(overall_score, 1),
        score_class=score_class,
        vuln_count=len(vulnerabilities),
        severity_counts=severity_counts,
        vulnerabilities=vulnerabilities,
        cve_details=cve_details,
        compliance_checks=compliance_checks or [],
        ai_insight=ai_insight,
        provider_statuses=provider_statuses or [],
        verdict_reason=(audit_verdict or {}).get("reason"),
        overall_verdict=(audit_verdict or {}).get("verdict") or ("Critical" if overall_score >= 75 else "High" if overall_score >= 50 else "Medium" if overall_score >= 25 else "Low"),
    )


def generate_report_html_document(
    scan_id: uuid.UUID,
    target: str,
    scan_type: str,
    overall_score: float,
    vulnerabilities: list[dict],
    cve_details: list[dict],
    compliance_checks: list[dict] | None = None,
    audit_verdict: dict | None = None,
    ai_insight: dict | None = None,
    provider_statuses: list[dict] | None = None,
    started_at=None,
    finished_at=None,
) -> str:
    return generate_html_report(
        scan_id=str(scan_id),
        target=target,
        scan_type=scan_type,
        overall_score=overall_score,
        vulnerabilities=vulnerabilities,
        cve_details=cve_details,
        compliance_checks=compliance_checks,
        audit_verdict=audit_verdict,
        ai_insight=ai_insight,
        provider_statuses=provider_statuses,
        started_at=str(started_at) if started_at else None,
        finished_at=str(finished_at) if finished_at else None,
    )


def build_report_payload(
    scan_id: uuid.UUID,
    target: str,
    scan_type: str,
    overall_score: float,
    vulnerabilities: list[dict],
    cve_details: list[dict],
    compliance_checks: list[dict] | None = None,
    audit_verdict: dict | None = None,
    ai_insight: dict | None = None,
    provider_statuses: list[dict] | None = None,
    started_at=None,
    finished_at=None,
) -> dict:
    vulnerabilities = prepare_findings_for_report(vulnerabilities)
    severity_counts = {}
    for v in vulnerabilities:
        sev = v.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total_checks = len(compliance_checks or [])
    passed_checks = sum(1 for item in (compliance_checks or []) if item.get("result") == "pass")
    compliance_score = round((passed_checks / total_checks) * 100, 2) if total_checks else None

    return redact_data({
        "report_id": str(scan_id),
        "target": target,
        "scan_type": scan_type,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "started_at": str(started_at) if started_at else None,
        "finished_at": str(finished_at) if finished_at else None,
        "overall_score": round(overall_score, 1),
        "overall_verdict": (audit_verdict or {}).get("verdict") or ("Critical" if overall_score >= 75 else "High" if overall_score >= 50 else "Medium" if overall_score >= 25 else "Low"),
        "verdict_reason": (audit_verdict or {}).get("reason"),
        "vulnerability_count": len(vulnerabilities),
        "severity_counts": severity_counts,
        "vulnerabilities": vulnerabilities,
        "cve_details": cve_details,
        "compliance_checks": compliance_checks or [],
        "compliance_score": compliance_score,
        "ai_insight": ai_insight,
        "provider_statuses": provider_statuses or [],
        "recommendations": [
            "Replace MD5/SHA-1 with SHA-256 or SHA-3",
            "Replace DES/3DES/RC2 with AES-256-GCM",
            "Use RSA >= 2048 bits or ECDSA >= P-256",
            "Enable TLS 1.2+ and disable older versions",
            "Enable HSTS with a minimum max-age of 31536000",
            "Use CA-trusted certificates with correct SANs and automated renewal",
            "Store secrets in a managed vault",
        ],
    })


def generate_pdf_report(html_content: str, output_path: str) -> str:
    async def _render() -> str:
        renderer = get_report_renderer()
        return await renderer.render_pdf(
            html_content,
            output_path,
            metadata={"header_text": settings.REPORT_PDF_HEADER, "footer_text": settings.REPORT_PDF_FOOTER},
        )

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_render())

    result: dict[str, str] = {}
    error: list[BaseException] = []

    def _worker() -> None:
        try:
            result["path"] = asyncio.run(_render())
        except BaseException as exc:  # pragma: no cover - thread handoff failure
            error.append(exc)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result["path"]


def build_report(
    scan_id: uuid.UUID,
    target: str,
    scan_type: str,
    overall_score: float,
    vulnerabilities: list[dict],
    cve_details: list[dict],
    compliance_checks: list[dict] | None = None,
    audit_verdict: dict | None = None,
    ai_insight: dict | None = None,
    provider_statuses: list[dict] | None = None,
    started_at=None,
    finished_at=None,
) -> str:
    reports_dir = os.path.join(settings.UPLOAD_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    html = generate_report_html_document(
        scan_id=scan_id,
        target=target,
        scan_type=scan_type,
        overall_score=overall_score,
        vulnerabilities=vulnerabilities,
        cve_details=cve_details,
        compliance_checks=compliance_checks,
        audit_verdict=audit_verdict,
        ai_insight=ai_insight,
        provider_statuses=provider_statuses,
        started_at=started_at,
        finished_at=finished_at,
    )

    pdf_path = os.path.join(reports_dir, f"{scan_id}.pdf")
    return generate_pdf_report(html, pdf_path)


def generate_markdown_report(payload: dict) -> str:
    payload = redact_data(payload)
    ai_insight = payload.get("ai_insight") or {}
    lines = [
        f"# VulNexus Security Report - {payload.get('target', 'Unknown Target')}",
        "",
        f"**Overall Risk:** {payload.get('overall_score', 0)} / 100",
        f"**Verdict:** {payload.get('overall_verdict', 'Low')}",
        f"**Generated:** {payload.get('generated_at', 'Not Applicable')}",
        "",
        "## Executive Summary",
        ai_insight.get("summary", "No executive summary available."),
        "",
        "## Risk Distribution",
        json.dumps(payload.get("severity_counts", {}), indent=2),
        "",
        "## Findings",
    ]
    provider_statuses = payload.get("provider_statuses") or []
    if provider_statuses:
        lines.extend(["", "## External Intelligence Provider Status"])
        for status in provider_statuses:
            lines.append(
                f"- {status.get('provider', 'Provider')}: {status.get('status', 'skipped')} — "
                f"{status.get('message') or status.get('error') or 'No usable provider data was returned.'}"
            )
    for finding in payload.get("vulnerabilities", []):
        lines.extend([
            f"### {finding.get('display_title') or get_finding_title(finding)}",
            f"Severity: {finding.get('severity', 'Unknown')}",
            f"Confidence: {finding.get('display_confidence') or _format_confidence(finding.get('confidence'))}",
            f"Affected Asset: {finding.get('display_location') or finding.get('file_path') or payload.get('target', 'Not Applicable')}",
            f"Description: {finding.get('description', '')}",
            f"Evidence: {finding.get('display_evidence') or _format_evidence(finding.get('evidence'))}",
            f"Risk: {finding.get('ml_score', 'Not Applicable')}",
            f"CVE: {finding.get('display_cve') or finding.get('cve_id') or 'Not Applicable'}",
            f"CVSS: {finding.get('display_cvss') or _format_cvss(finding.get('cvss_score'))}",
            f"Attack Story: {finding.get('attack_story') or finding.get('knowledge', {}).get('attack', {}).get('attack_story', 'Not Applicable')}",
            f"Mitigation: {finding.get('remediation') or 'Review and remediate.'}",
            "",
        ])
    lines.extend([
        "## Recommendations",
        *[f"- {item}" for item in payload.get("recommendations", [])],
        "",
        "## References",
    ])
    references = []
    for finding in payload.get("vulnerabilities", []):
        for reference in finding.get("references") or []:
            if reference and reference not in references:
                references.append(reference)
    lines.extend(f"- {reference}" for reference in references[:50])
    return "\n".join(lines).strip() + "\n"


def generate_csv_report(payload: dict, output_path: str) -> str:
    payload = redact_data(payload)

    def csv_safe(value) -> str:
        """Prevent spreadsheet applications from interpreting untrusted cells as formulas."""
        text = "" if value is None else str(value)
        return f"'{text}" if text.lstrip().startswith(("=", "+", "-", "@")) else text

    with open(output_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["finding", "severity", "confidence", "description", "risk_score", "cve", "cvss", "remediation", "affected_asset", "evidence"])
        for finding in payload.get("vulnerabilities", []):
            writer.writerow([
                csv_safe(finding.get("display_title") or get_finding_title(finding)),
                csv_safe(finding.get("severity")),
                csv_safe(finding.get("display_confidence") or _format_confidence(finding.get("confidence"))),
                csv_safe(finding.get("description")),
                csv_safe(finding.get("ml_score")),
                csv_safe(finding.get("display_cve") or finding.get("cve_id") or "Not Applicable"),
                csv_safe(finding.get("display_cvss") or _format_cvss(finding.get("cvss_score"))),
                csv_safe(finding.get("remediation")),
                csv_safe(finding.get("display_location") or finding.get("file_path") or "Not Applicable"),
                csv_safe(finding.get("display_evidence") or _format_evidence(finding.get("evidence"))),
            ])
    return output_path


def generate_docx_report(payload: dict, output_path: str) -> str:
    payload = redact_data(payload)
    document_xml = _build_docx_document_xml(payload)
    with ZipFile(output_path, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _docx_content_types())
        archive.writestr("_rels/.rels", _docx_root_rels())
        archive.writestr("word/document.xml", document_xml)
    return output_path


def generate_report_markdown_document(payload: dict) -> str:
    return generate_markdown_report(payload)


def export_report_document(payload: dict, output_path: str, format: str) -> str:
    payload = redact_data(payload)
    report_format = format.lower()
    if report_format == "md":
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(generate_markdown_report(payload))
        return output_path
    if report_format == "csv":
        return generate_csv_report(payload, output_path)
    if report_format == "docx":
        return generate_docx_report(payload, output_path)
    if report_format == "json":
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(redact_data(payload), handle, indent=2, default=str)
        return output_path
    if report_format == "html":
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(generate_html_report(
                scan_id=payload.get("report_id", "unknown"),
                target=payload.get("target", "Unknown Target"),
                scan_type=payload.get("scan_type", "unknown"),
                overall_score=float(payload.get("overall_score", 0) or 0),
                vulnerabilities=payload.get("vulnerabilities", []),
                cve_details=payload.get("cve_details", []),
                compliance_checks=payload.get("compliance_checks", []),
                audit_verdict={"verdict": payload.get("overall_verdict"), "reason": payload.get("verdict_reason")},
                ai_insight=payload.get("ai_insight"),
                started_at=payload.get("started_at"),
                finished_at=payload.get("finished_at"),
            ))
        return output_path
    raise ValueError(f"Unsupported report format: {format}")


def _build_docx_document_xml(payload: dict) -> str:
    target = payload.get("target", "Unknown Target")
    severity_counts = payload.get("severity_counts", {})
    ai_summary = (payload.get("ai_insight") or {}).get("summary") or "No executive summary available."
    body = [
        _docx_paragraph("VulNexus Security Report", size=34, bold=True, color="1D4ED8"),
        _docx_paragraph(str(target), size=24, bold=True),
        _docx_paragraph(f"Generated: {payload.get('generated_at', 'Not Applicable')}"),
        _docx_paragraph(f"Overall risk: {payload.get('overall_score', 0)} / 100 | Verdict: {payload.get('overall_verdict', 'Low')}", bold=True),
        _docx_paragraph("Executive Summary", size=24, bold=True, color="0F172A"),
        _docx_paragraph(ai_summary),
        _docx_paragraph("Risk Distribution", size=22, bold=True, color="0F172A"),
        _docx_table(
            ["Critical", "High", "Medium", "Low", "Total Findings"],
            [[
                severity_counts.get("Critical", 0),
                severity_counts.get("High", 0),
                severity_counts.get("Medium", 0),
                severity_counts.get("Low", 0),
                payload.get("vulnerability_count", 0),
            ]],
        ),
        _docx_paragraph("Prioritized Findings and Remediation", size=22, bold=True, color="0F172A"),
    ]
    for index, finding in enumerate(payload.get("vulnerabilities", [])[:30], start=1):
        title = finding.get("display_title") or get_finding_title(finding)
        body.extend([
            _docx_paragraph(f"{index}. {title}", size=20, bold=True, color=_docx_severity_color(finding.get("severity"))),
            _docx_paragraph(f"Severity: {finding.get('severity', 'Unknown')} | Confidence: {finding.get('display_confidence', 'Not Applicable')}", bold=True),
            _docx_paragraph(f"Affected asset: {finding.get('display_location') or finding.get('file_path') or target}"),
            _docx_paragraph(f"Evidence: {finding.get('display_evidence') or _format_evidence(finding.get('evidence'))}"),
            _docx_paragraph(f"Remediation: {finding.get('remediation') or 'Review and remediate.'}"),
            _docx_paragraph("Verification: rerun the same scan, confirm this rule no longer appears, and review related findings before closing."),
        ])
    body.extend([
        _docx_paragraph("General Remediation Checklist", size=22, bold=True, color="0F172A"),
        _docx_paragraph("1. Fix critical and high findings first."),
        _docx_paragraph("2. Rotate exposed or hardcoded secrets after removal."),
        _docx_paragraph("3. Add regression tests or configuration checks for corrected weaknesses."),
        _docx_paragraph("4. Regenerate reports after validation so evidence remains current."),
    ])
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">"
        f"<w:body>{''.join(body)}"
        "<w:sectPr><w:pgSz w:w=\"12240\" w:h=\"15840\"/><w:pgMar w:top=\"1080\" w:right=\"1080\" w:bottom=\"1080\" w:left=\"1080\"/></w:sectPr>"
        "</w:body></w:document>"
    )


def _docx_paragraph(text: str, *, size: int = 20, bold: bool = False, color: str = "0F172A") -> str:
    bold_xml = "<w:b/>" if bold else ""
    return (
        "<w:p><w:pPr><w:spacing w:after=\"160\"/></w:pPr><w:r>"
        f"<w:rPr>{bold_xml}<w:color w:val=\"{color}\"/><w:sz w:val=\"{size}\"/></w:rPr>"
        f"<w:t>{escape(str(text))}</w:t></w:r></w:p>"
    )


def _docx_table(headers: list[str], rows: list[list[object]]) -> str:
    def cell(value: object, *, header: bool = False) -> str:
        fill = "<w:shd w:fill=\"DBEAFE\"/>" if header else ""
        return f"<w:tc><w:tcPr>{fill}</w:tcPr>{_docx_paragraph(str(value), bold=header)}</w:tc>"

    header_row = "<w:tr>" + "".join(cell(header, header=True) for header in headers) + "</w:tr>"
    row_xml = "".join("<w:tr>" + "".join(cell(value) for value in row) + "</w:tr>" for row in rows)
    return f"<w:tbl><w:tblPr><w:tblW w:w=\"0\" w:type=\"auto\"/><w:tblBorders><w:top w:val=\"single\" w:sz=\"4\"/><w:left w:val=\"single\" w:sz=\"4\"/><w:bottom w:val=\"single\" w:sz=\"4\"/><w:right w:val=\"single\" w:sz=\"4\"/><w:insideH w:val=\"single\" w:sz=\"4\"/><w:insideV w:val=\"single\" w:sz=\"4\"/></w:tblBorders></w:tblPr>{header_row}{row_xml}</w:tbl>"


def _docx_severity_color(severity: str | None) -> str:
    return {
        "Critical": "991B1B",
        "High": "C2410C",
        "Medium": "A16207",
        "Low": "166534",
    }.get(str(severity), "1D4ED8")


def _docx_content_types() -> str:
    return """<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>"""


def _docx_root_rels() -> str:
    return """<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>"""
