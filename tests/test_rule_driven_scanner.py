from __future__ import annotations

import json

import pytest

from app.services.file_scanner import MAX_FINDINGS_PER_FILE, scan_file_content
from app.services.report_generator import build_report_payload, generate_html_report, generate_markdown_report
from app.services.rule_loader import RuleValidationError, load_rule_pack, load_scanner_rules


def test_master_rule_pack_loads_crypto_and_application_rules_once():
    rules = load_scanner_rules()
    assert len(rules) == 104
    assert len({rule.id for rule in rules}) == len(rules)
    assert {"Weak hashing", "Hardcoded keys", "Insecure randomness", "Poor key management", "TLS misconfiguration", "Weak cryptographic modes", "Dangerous execution"}.issubset(
        {rule.category for rule in rules}
    )
    assert all(rule.cvss_hint is not None for rule in rules)
    assert {"crypto_audit", "application_security"} == {rule.pack for rule in rules}


def test_malformed_rule_pack_is_rejected(tmp_path):
    bad_pack = tmp_path / "bad.yml"
    bad_pack.write_text(
        """
version: "1.0"
categories:
  weak_hashing:
    - id: ONLY_ID
""",
        encoding="utf-8",
    )

    with pytest.raises(RuleValidationError):
        load_rule_pack(bad_pack)


def test_sample_scan_proves_source_categories_work():
    code = """
import hashlib, random
digest = hashlib.md5(password.encode()).hexdigest()
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
reset_token = random.random()
iv = "0000000000000000"
ssl_protocols TLSv1 TLSv1.1;
    cipher = AES.new(key, AES.MODE_ECB)
"""
    findings, _ = scan_file_content(code, "demo.py")
    categories = {finding.category for finding in findings}

    assert {
        "Weak hashing",
        "Hardcoded keys",
        "Insecure randomness",
        "Poor key management",
        "TLS misconfiguration",
        "Weak cryptographic modes",
    }.issubset(categories)
    assert all(finding.rule_id for finding in findings)
    assert all(finding.evidence.get("source_rule_id") for finding in findings)


def test_multiple_matches_for_same_legacy_rule_are_reported_with_columns():
    code = """
token_a = hashlib.md5(first_secret).hexdigest()
token_b = hashlib.md5(second_secret).hexdigest()
"""
    findings, _ = scan_file_content(code, "tokens.py")
    md5_findings = [finding for finding in findings if finding.rule_id == "WEAK_HASH_MD5_PY_HASHLIB"]

    assert len(md5_findings) == 2
    assert {finding.line_number for finding in md5_findings} == {2, 3}
    assert all(finding.column_number for finding in md5_findings)


def test_overlapping_secret_rules_are_deduplicated_to_specific_finding():
    code = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n'
    findings, _ = scan_file_content(code, "settings.env")
    hardcoded = [finding for finding in findings if finding.rule_id == "HARDCODED_AWS_ACCESS_KEY"]

    assert len(hardcoded) == 1
    assert hardcoded[0].evidence["source_rule_id"] == "HARDCODED_AWS_ACCESS_KEY"


def test_finding_limits_report_suppressed_count():
    code = "\n".join(f"token_{i} = hashlib.md5(secret_{i}).hexdigest()" for i in range(MAX_FINDINGS_PER_FILE + 5))
    findings, _ = scan_file_content(code, "many_tokens.py")

    assert len(findings) == 25
    # The semantic engine emits one canonical AST finding per call site,
    # instead of duplicating the same source location through overlapping
    # regex rules.
    assert findings[0].evidence["suppressed_count"] == 5


def test_secret_redaction_reaches_scanner_payload_html_and_markdown():
    raw_values = [
        "abc123demo456secret789",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "super-secret-value",
        "password123",
        "P@ssw0rd!",
    ]
    code = """
GCP_PRIVATE_KEY_ID=abc123demo456secret789
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
CLIENT_SECRET: super-secret-value
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signaturepart
DATABASE_URL=postgresql://admin:password123@localhost/db
password = "P@ssw0rd!"
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC
-----END PRIVATE KEY-----
"""
    findings, _ = scan_file_content(code, "secrets.env")
    scanner_json = json.dumps([finding.model_dump() for finding in findings], default=str)
    payload = build_report_payload(
        scan_id="00000000-0000-0000-0000-000000000001",
        target="secret demo",
        scan_type="file",
        overall_score=90,
        vulnerabilities=[finding.model_dump() for finding in findings],
        cve_details=[],
    )
    html = generate_html_report(
        scan_id=payload["report_id"],
        target=payload["target"],
        scan_type=payload["scan_type"],
        overall_score=payload["overall_score"],
        vulnerabilities=payload["vulnerabilities"],
        cve_details=[],
    )
    markdown = generate_markdown_report(payload)

    for raw in raw_values:
        assert raw not in scanner_json
        assert raw not in json.dumps(payload, default=str)
        assert raw not in html
        assert raw not in markdown
    assert "GCP_PRIVATE_KEY_ID" in scanner_json
    assert "[REDACTED]" in scanner_json


def test_html_report_escapes_untrusted_fields_but_keeps_report_markup():
    malicious = '<script>alert("xss")</script>'
    finding = {
        "rule_id": "HARDCODED_KEY",
        "title": malicious,
        "category": "Hardcoded keys",
        "severity": "Critical",
        "confidence": 0.97,
        "file_path": '"><svg/onload=alert(1)>',
        "line_number": 7,
        "column_number": 3,
        "description": '<img src=x onerror=alert(1)>',
        "remediation": malicious,
        "evidence": {"line_preview": malicious, "header": '<img src=x onerror=alert(1)>'},
        "cwe_ids": ["CWE-798"],
        "owasp_category": "A07 Identification and Authentication Failures",
    }

    html = generate_html_report(
        scan_id="00000000-0000-0000-0000-000000000001",
        target=malicious,
        scan_type="file",
        overall_score=88,
        vulnerabilities=[finding],
        cve_details=[],
    )

    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "<svg/onload" not in html
    assert "&lt;script&gt;" in html
    assert "<section class=\"cover\">" in html
    assert "</html>" in html
