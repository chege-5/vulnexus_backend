from __future__ import annotations

from collections import Counter
from typing import Iterable


RULE_PROFILE_MAP = {
    "WEAK_HASH_MD5": {
        "owasp_category": "A02 Cryptographic Failures",
        "nist_control": "SC-13",
        "cwe_ids": ["CWE-327"],
        "mitre_technique": "T1027",
        "cis_control": "3.11",
    },
    "WEAK_HASH_SHA1": {
        "owasp_category": "A02 Cryptographic Failures",
        "nist_control": "SC-13",
        "cwe_ids": ["CWE-327"],
        "mitre_technique": "T1027",
        "cis_control": "3.11",
    },
    "WEAK_CIPHER_DES": {
        "owasp_category": "A02 Cryptographic Failures",
        "nist_control": "SC-12",
        "cwe_ids": ["CWE-326"],
        "mitre_technique": "T1573",
        "cis_control": "3.4",
    },
    "WEAK_CIPHER_RC2": {
        "owasp_category": "A02 Cryptographic Failures",
        "nist_control": "SC-12",
        "cwe_ids": ["CWE-326"],
        "mitre_technique": "T1573",
        "cis_control": "3.4",
    },
    "WEAK_CIPHER_AES-ECB": {
        "owasp_category": "A02 Cryptographic Failures",
        "nist_control": "SC-12",
        "cwe_ids": ["CWE-327"],
        "mitre_technique": "T1573",
        "cis_control": "3.4",
    },
    "SMALL_RSA_KEY": {
        "owasp_category": "A02 Cryptographic Failures",
        "nist_control": "SC-12",
        "cwe_ids": ["CWE-310"],
        "mitre_technique": "T1600",
        "cis_control": "3.6",
    },
    "SMALL_AES_KEY": {
        "owasp_category": "A02 Cryptographic Failures",
        "nist_control": "SC-13",
        "cwe_ids": ["CWE-326"],
        "mitre_technique": "T1600",
        "cis_control": "3.6",
    },
    "HARDCODED_KEY": {
        "owasp_category": "A07 Identification and Authentication Failures",
        "nist_control": "IA-5",
        "cwe_ids": ["CWE-798"],
        "mitre_technique": "T1552",
        "cis_control": "3.5",
    },
    "INSECURE_RANDOM": {
        "owasp_category": "A02 Cryptographic Failures",
        "nist_control": "SC-32",
        "cwe_ids": ["CWE-330"],
        "mitre_technique": "T1600",
        "cis_control": "3.2",
    },
    "WEAK_TLS_VERSION": {
        "owasp_category": "A02 Cryptographic Failures",
        "nist_control": "SC-8",
        "cwe_ids": ["CWE-319"],
        "mitre_technique": "T1040",
        "cis_control": "4.2",
    },
    "SELF_SIGNED_CERT": {
        "owasp_category": "A05 Security Misconfiguration",
        "nist_control": "SC-12",
        "cwe_ids": ["CWE-295"],
        "mitre_technique": "T1553",
        "cis_control": "4.2",
    },
    "NO_HSTS": {
        "owasp_category": "A05 Security Misconfiguration",
        "nist_control": "SC-8",
        "cwe_ids": ["CWE-693"],
        "mitre_technique": "T1040",
        "cis_control": "4.1",
    },
}


def infer_vulnerability_profile(rule_id: str | None, severity: str | None, cve_id: str | None = None, cvss_score: float | None = None) -> dict:
    profile = RULE_PROFILE_MAP.get(rule_id or "", {})
    base_cwe = profile.get("cwe_ids", [])
    if cve_id and cvss_score is not None and cvss_score >= 9:
        result = "fail"
    elif severity in {"Critical", "High"} or (cvss_score is not None and cvss_score >= 7):
        result = "warning"
    elif severity == "Medium":
        result = "warning"
    else:
        result = "pass"

    return {
        "owasp_category": profile.get("owasp_category"),
        "nist_control": profile.get("nist_control"),
        "cwe_ids": base_cwe,
        "mitre_technique": profile.get("mitre_technique"),
        "cis_control": profile.get("cis_control"),
        "known_exploit": bool(cve_id and cvss_score is not None and cvss_score >= 7),
        "result": result,
    }


def build_compliance_checks(
    vulnerabilities: list[dict],
    cve_details: list[dict],
) -> list[dict]:
    cve_map = {item.get("cve_id"): item for item in cve_details if item.get("cve_id")}
    checks: list[dict] = []

    for vuln in vulnerabilities:
        rule_id = vuln.get("rule_id")
        cve_id = vuln.get("cve_id")
        severity = vuln.get("severity")
        cve_entry = cve_map.get(cve_id) if cve_id else None
        cvss_score = cve_entry.get("cvss_score") if cve_entry else vuln.get("cvss_score")
        profile = infer_vulnerability_profile(rule_id, severity, cve_id=cve_id, cvss_score=cvss_score)

        standard_rows = [
            ("owasp_top_10", profile.get("owasp_category")),
            ("nist", profile.get("nist_control")),
            ("cwe", ", ".join(profile.get("cwe_ids") or []) or None),
            ("cve", cve_id),
            ("cvss", f"{cvss_score:.1f}" if isinstance(cvss_score, (int, float)) else None),
            ("mitre_attack", profile.get("mitre_technique")),
            ("cis", profile.get("cis_control")),
        ]

        for standard, category in standard_rows:
            if not category:
                continue
            result = profile["result"]
            score = 100.0 if result == "pass" else 60.0 if result == "warning" else 0.0
            if standard == "cve" and not cve_id:
                continue
            checks.append({
                "standard": standard,
                "category": category,
                "result": result,
                "score": score,
                "details": {
                    "rule_id": rule_id,
                    "severity": severity,
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "description": vuln.get("description"),
                },
            })

    return checks


def derive_final_audit_verdict(
    overall_score: float,
    compliance_score: float | None,
    critical_findings: int,
    high_findings: int,
    cve_count: int,
    known_exploit_count: int = 0,
) -> dict:
    compliance_pressure = 100 - compliance_score if compliance_score is not None else 35
    combined = (overall_score * 0.55) + (compliance_pressure * 0.25) + (critical_findings * 18) + (high_findings * 8) + (cve_count * 3) + (known_exploit_count * 6)

    if critical_findings > 0 or combined >= 110:
        verdict = "Critical"
        status = "fail"
    elif combined >= 75:
        verdict = "High"
        status = "fail"
    elif combined >= 45:
        verdict = "Medium"
        status = "warning"
    else:
        verdict = "Low"
        status = "pass"

    reason = (
        f"Risk score {overall_score:.1f}/100, compliance {compliance_score:.1f}%" if compliance_score is not None else f"Risk score {overall_score:.1f}/100"
    )
    reason += f", {critical_findings} critical, {high_findings} high findings, {cve_count} CVE-linked issues"
    if known_exploit_count:
        reason += f", {known_exploit_count} known exploit signals"

    return {
        "verdict": verdict,
        "status": status,
        "reason": reason,
        "combined_score": round(combined, 2),
    }


def build_ai_insight(
    target: str,
    scan_type: str,
    overall_score: float,
    compliance_score: float | None,
    verdict: dict,
    vulnerabilities: Iterable[dict],
) -> dict:
    vuln_list = list(vulnerabilities)
    counts = Counter((item.get("severity") or "Unknown") for item in vuln_list)
    top_rules = [item.get("rule_id") or item.get("description") or "Finding" for item in vuln_list[:3]]
    summary_bits = [
        f"{verdict['verdict']} audit verdict for {target} ({scan_type}).",
        f"Risk score {overall_score:.1f}/100.",
    ]
    if compliance_score is not None:
        summary_bits.append(f"Compliance score {compliance_score:.1f}%.")
    if top_rules:
        summary_bits.append("Primary drivers: " + ", ".join(top_rules))
    if counts.get("Critical"):
        summary_bits.append(f"{counts['Critical']} critical findings need immediate remediation.")

    return {
        "title": f"AI Audit Insight — {target}",
        "summary": " ".join(summary_bits),
        "message": " ".join(summary_bits),
        "severity": verdict["verdict"],
        "target": target,
        "type": scan_type,
    }