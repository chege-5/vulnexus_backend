import asyncio
import os
import threading
import uuid
from datetime import datetime
from typing import Optional
from jinja2 import Template
from app.config import settings
from app.services.report_renderer import get_report_renderer
from app.utils.logger import get_logger

logger = get_logger(__name__)

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
    <p>Enterprise-grade cryptography, transport, secrets, and repository security assessment for {{ scan_type|upper }} targets. This report consolidates SAST, DAST, AI risk analysis, and compliance signal into a single audit artifact.</p>
    <p><strong>Report ID:</strong> {{ scan_id }}<br><strong>Generated:</strong> {{ generated_at }}<br><strong>Started:</strong> {{ started_at or 'N/A' }}<br><strong>Finished:</strong> {{ finished_at or 'N/A' }}</p>
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
                <th>#</th><th>Severity</th><th>Rule ID</th><th>Description</th><th>Score</th><th>CVE / CVSS</th><th>Location</th>
            </tr>
        </thead>
        <tbody>
        {% for v in vulnerabilities %}
            <tr>
                <td>{{ loop.index }}</td>
                <td><span class="pill {{ v.severity|lower }}">{{ v.severity }}</span></td>
                <td>{{ v.rule_id or 'N/A' }}</td>
                <td>{{ v.description }}</td>
                <td>{{ v.ml_score if v.ml_score is not none else 'N/A' }}</td>
                <td>{{ v.cve_id or 'N/A' }}</td>
                <td>{{ v.file_path or 'N/A' }}{% if v.line_number %}:{{ v.line_number }}{% endif %}</td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p>No vulnerabilities detected.</p>
    {% endif %}
</section>

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
                <td>{{ check.category or 'N/A' }}</td>
                <td>{{ check.result }}</td>
                <td>{{ check.score if check.score is not none else 'N/A' }}</td>
                <td>{{ check.details.rule_id if check.details and check.details.rule_id else 'N/A' }}</td>
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
                <td>{{ c.cvss_score or 'N/A' }}</td>
                <td>{{ c.summary or 'N/A' }}</td>
                <td>{{ c.published_date or 'N/A' }}</td>
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
            <h3>{{ v.rule_id or 'Issue' }} - {{ v.severity }}</h3>
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
    <div>Generated by VulNexus - AI-Based Cryptography Vulnerability Scanner</div>
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
    "SMALL_RSA_KEY": "Use RSA key size of 2048 bits minimum (NIST recommendation). Consider 4096 for long-term security.",
    "SMALL_AES_KEY": "Use AES-128 minimum; AES-256 recommended for sensitive data.",
    "HARDCODED_KEY": "Move keys to environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
    "INSECURE_RANDOM": "Use os.urandom(), secrets module (Python), or java.security.SecureRandom (Java).",
    "WEAK_TLS_VERSION": "Disable TLS 1.0/1.1 and enable TLS 1.2+ (PCI DSS 3.2 requirement).",
    "SELF_SIGNED_CERT": "Use certificates from a trusted CA. Use Let's Encrypt for free certificates.",
    "NO_HSTS": "Add Strict-Transport-Security header with max-age=31536000; includeSubDomains.",
    "NO_FORWARD_SECRECY": "Configure server to prefer ECDHE cipher suites for forward secrecy.",
    "EXPIRED_CERT": "Renew the expired certificate immediately. Set up automated renewal.",
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
    started_at: Optional[str] = None,
    finished_at: Optional[str] = None,
) -> str:
    for v in vulnerabilities:
        if not v.get("remediation") and v.get("rule_id"):
            v["remediation"] = get_remediation(v["rule_id"])

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

    template = Template(REPORT_TEMPLATE)
    return template.render(
        scan_id=scan_id,
        target=target,
        scan_type=scan_type,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
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
    started_at=None,
    finished_at=None,
) -> dict:
    severity_counts = {}
    for v in vulnerabilities:
        sev = v.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total_checks = len(compliance_checks or [])
    passed_checks = sum(1 for item in (compliance_checks or []) if item.get("result") == "pass")
    compliance_score = round((passed_checks / total_checks) * 100, 2) if total_checks else None

    return {
        "report_id": str(scan_id),
        "target": target,
        "scan_type": scan_type,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
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
        "recommendations": [
            "Replace MD5/SHA-1 with SHA-256 or SHA-3",
            "Replace DES/3DES/RC2 with AES-256-GCM",
            "Use RSA >= 2048 bits or ECDSA >= P-256",
            "Enable TLS 1.2+ and disable older versions",
            "Enable HSTS with a minimum max-age of 31536000",
            "Store secrets in a managed vault",
        ],
    }


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
        started_at=started_at,
        finished_at=finished_at,
    )

    pdf_path = os.path.join(reports_dir, f"{scan_id}.pdf")
    return generate_pdf_report(html, pdf_path)
